use sha2::{Digest, Sha256};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use crate::fingerprint::compute_fingerprint;

pub const MASTER_SECRET: &str = "Lab2_DRM_MasterSecret_2024";
const LICENSES_DIR: &str = "licenses";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct License {
    pub key: String,           // hex-encoded license key
    pub fingerprint: String,   // hardware fingerprint at creation
    pub filename: String,      // имя защищаемого файла
}

pub fn licenses_dir() -> PathBuf {
    let exe = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("."));
    exe.parent().unwrap_or_else(|| std::path::Path::new("."))
        .join(LICENSES_DIR)
}

fn license_path(filename: &str) -> PathBuf {
    licenses_dir().join(format!("{}.license", filename))
}

/// Сгенерировать лицензионный ключ, привязанный к текущему железу.
pub fn generate_key(filename: &str) -> String {
    let fp = compute_fingerprint();
    let raw = format!("{}|{}|{}", MASTER_SECRET, fp, filename);
    let mut h = Sha256::new();
    h.update(raw.as_bytes());
    let hash = hex::encode(h.finalize());
    // Формат ключа: XXXX-XXXX-XXXX-XXXX (первые 16 hex символов)
    let s = &hash[..16].to_uppercase();
    format!("{}-{}-{}-{}", &s[0..4], &s[4..8], &s[8..12], &s[12..16])
}

/// Сохранить лицензию на диск
pub fn save_license(filename: &str, key: &str) -> std::io::Result<()> {
    std::fs::create_dir_all(licenses_dir())?;
    let lic = License {
        key: key.to_string(),
        fingerprint: compute_fingerprint(),
        filename: filename.to_string(),
    };
    let json = serde_json::to_string_pretty(&lic).unwrap();
    std::fs::write(license_path(filename), json)
}

/// Загрузить лицензию из файла
pub fn load_license(filename: &str) -> Option<License> {
    let raw = std::fs::read_to_string(license_path(filename)).ok()?;
    serde_json::from_str(&raw).ok()
}

/// Проверить лицензионный ключ для файла на текущем железе
pub fn verify_key(filename: &str, key: &str) -> bool {
    let expected = generate_key(filename);
    expected.eq_ignore_ascii_case(key)
}

/// Проверить сохранённую лицензию
pub fn verify_license(filename: &str) -> bool {
    match load_license(filename) {
        Some(lic) => {
            let fp = compute_fingerprint();
            lic.fingerprint == fp && verify_key(filename, &lic.key)
        }
        None => false,
    }
}
