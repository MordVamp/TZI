use sha2::{Digest, Sha256};
use sysinfo::System;

/// ПГ-2: вычислить сигнатуру компьютера из 5+ параметров.
/// Параметры (адаптировано для Linux):
///   1. Имя пользователя ОС
///   2. Имя компьютера (hostname)
///   3. Путь к корневому разделу ОС
///   4. Объём RAM (суммарный, МБ)
///   5. Информация о корневом диске (размер, тип ФС)
pub fn compute_signature() -> String {
    let mut sys = System::new_all();
    sys.refresh_all();

    let os_user = std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "unknown".to_string());

    let hostname = System::host_name().unwrap_or_else(|| "unknown".to_string());

    let os_root = "/".to_string();

    let total_ram_mb = sys.total_memory() / 1024 / 1024;

    // Информация о диске
    let disk_info = get_root_disk_info();

    let raw = format!(
        "{}|{}|{}|{}|{}",
        os_user, hostname, os_root, total_ram_mb, disk_info
    );

    let mut hasher = Sha256::new();
    hasher.update(raw.as_bytes());
    hex::encode(hasher.finalize())
}

/// Возвращает читаемое описание параметров сигнатуры (для отображения в UI)
pub fn signature_params() -> Vec<(String, String)> {
    let mut sys = System::new_all();
    sys.refresh_all();

    let os_user = std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "unknown".to_string());

    let hostname = System::host_name().unwrap_or_else(|| "unknown".to_string());
    let total_ram_mb = sys.total_memory() / 1024 / 1024;
    let disk_info = get_root_disk_info();

    vec![
        ("Пользователь ОС".into(), os_user),
        ("Имя компьютера".into(), hostname),
        ("Корневой раздел".into(), "/".into()),
        ("ОЗУ (МБ)".into(), total_ram_mb.to_string()),
        ("Диск".into(), disk_info),
    ]
}

fn get_root_disk_info() -> String {
    // Читаем /proc/mounts для корня
    let mounts = std::fs::read_to_string("/proc/mounts").unwrap_or_default();
    for line in mounts.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 3 && parts[1] == "/" {
            let fs_type = parts[2];
            // Размер через statvfs
            let size_gb = root_size_gb().unwrap_or(0);
            return format!("{}:{}GB", fs_type, size_gb);
        }
    }
    "unknown".to_string()
}

fn root_size_gb() -> Option<u64> {
    use std::mem::MaybeUninit;
    unsafe {
        let mut stat: MaybeUninit<libc::statvfs> = MaybeUninit::uninit();
        let path = std::ffi::CString::new("/").ok()?;
        if libc::statvfs(path.as_ptr(), stat.as_mut_ptr()) != 0 {
            return None;
        }
        let stat = stat.assume_init();
        Some(stat.f_blocks * stat.f_frsize / 1024 / 1024 / 1024)
    }
}
