use sha2::{Digest, Sha256};
use sysinfo::System;

/// Отпечаток аппаратуры: username + hostname + RAM_MB
pub fn compute_fingerprint() -> String {
    let mut sys = System::new_all();
    sys.refresh_all();

    let user = std::env::var("USER").unwrap_or_else(|_| "unknown".into());
    let host = System::host_name().unwrap_or_else(|| "unknown".into());
    let ram = sys.total_memory() / 1024 / 1024;

    let raw = format!("{}|{}|{}", user, host, ram);
    let mut h = Sha256::new();
    h.update(raw.as_bytes());
    hex::encode(h.finalize())
}

/// Получить читаемые параметры отпечатка
pub fn fingerprint_params() -> Vec<(String, String)> {
    let mut sys = System::new_all();
    sys.refresh_all();
    vec![
        ("Пользователь ОС".into(),
         std::env::var("USER").unwrap_or_else(|_| "unknown".into())),
        ("Имя компьютера".into(),
         System::host_name().unwrap_or_else(|| "unknown".into())),
        ("ОЗУ (МБ)".into(),
         (sys.total_memory() / 1024 / 1024).to_string()),
    ]
}
