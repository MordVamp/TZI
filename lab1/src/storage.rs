use aes::Aes256;
use cbc::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit, block_padding::Pkcs7};
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

use crate::model::{Settings, User, UserDb};

type Aes256CbcEnc = cbc::Encryptor<Aes256>;
type Aes256CbcDec = cbc::Decryptor<Aes256>;

// ─── Пути к файлам ───────────────────────────────────────────────────────────
pub fn data_dir() -> PathBuf {
    let exe = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("."));
    exe.parent()
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf()
}

pub fn users_path() -> PathBuf {
    data_dir().join("users.dat")
}

pub fn settings_path() -> PathBuf {
    data_dir().join("settings.json")
}

// ─── Хэш пароля ─────────────────────────────────────────────────────────────
pub fn hash_password(password: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    hex::encode(hasher.finalize())
}

pub fn verify_password(user: &User, password: &str) -> bool {
    user.password_hash == hash_password(password)
}

// ─── AES-256-CBC шифрование ──────────────────────────────────────────────────
const SECRET: &[u8] = b"Lab1_PASZI_SecretKey_2024_xX!@#$"; // 32 байта

fn derive_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    let mut hasher = Sha256::new();
    hasher.update(SECRET);
    key.copy_from_slice(&hasher.finalize());
    key
}

fn encrypt(plaintext: &[u8]) -> Vec<u8> {
    let key = derive_key();
    let mut iv = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut iv);

    let enc = Aes256CbcEnc::new(&key.into(), &iv.into());
    let mut buf = vec![0u8; plaintext.len() + 16];
    buf[..plaintext.len()].copy_from_slice(plaintext);
    let ciphertext = enc
        .encrypt_padded_mut::<Pkcs7>(&mut buf, plaintext.len())
        .expect("encrypt failed");
    let mut result = iv.to_vec();
    result.extend_from_slice(ciphertext);
    result
}

fn decrypt(data: &[u8]) -> Option<Vec<u8>> {
    if data.len() < 16 {
        return None;
    }
    let key = derive_key();
    let (iv, ciphertext) = data.split_at(16);
    let dec = Aes256CbcDec::new(key.as_ref().into(), iv.into());
    let mut buf = ciphertext.to_vec();
    dec.decrypt_padded_mut::<Pkcs7>(&mut buf).ok().map(|b| b.to_vec())
}

// ─── Загрузка / сохранение пользователей ────────────────────────────────────
pub fn load_users() -> UserDb {
    let path = users_path();
    if !path.exists() {
        let mut db = UserDb::default();
        db.add(User::new_admin());
        save_users(&db);
        return db;
    }

    let raw = std::fs::read(&path).unwrap_or_default();
    let json = decrypt(&raw)
        .and_then(|b| String::from_utf8(b).ok())
        .unwrap_or_default();

    serde_json::from_str::<UserDb>(&json).unwrap_or_else(|_| {
        let mut db = UserDb::default();
        db.add(User::new_admin());
        db
    })
}

pub fn save_users(db: &UserDb) {
    let json = serde_json::to_string_pretty(db).expect("serialize failed");
    let encrypted = encrypt(json.as_bytes());
    let path = users_path();
    std::fs::write(&path, encrypted).expect("write users failed");
}

// ─── Загрузка / сохранение настроек ─────────────────────────────────────────
pub fn load_settings() -> Settings {
    let path = settings_path();
    if !path.exists() {
        let s = Settings::default();
        save_settings(&s);
        return s;
    }
    let raw = std::fs::read_to_string(&path).unwrap_or_default();
    serde_json::from_str(&raw).unwrap_or_default()
}

pub fn save_settings(s: &Settings) {
    let json = serde_json::to_string_pretty(s).expect("serialize failed");
    std::fs::write(settings_path(), json).expect("write settings failed");
}

// ─── ПГ-1: работа с сертификатом на USB ─────────────────────────────────────
pub fn cert_path_for_user(username: &str, cert_drive: &str) -> PathBuf {
    PathBuf::from(cert_drive).join(format!("{}.cert", username))
}

/// Записать сертификат пользователя на USB-носитель
pub fn write_certificate(username: &str, password_hash: &str, cert_drive: &str) -> std::io::Result<()> {
    let path = cert_path_for_user(username, cert_drive);
    let content = serde_json::json!({
        "username": username,
        "hash": password_hash,
    });
    std::fs::write(path, content.to_string())
}

/// Прочитать и проверить сертификат с USB-носителя
pub fn verify_certificate(username: &str, cert_drive: &str) -> Option<String> {
    let path = cert_path_for_user(username, cert_drive);
    if !path.exists() {
        return None;
    }
    let raw = std::fs::read_to_string(path).ok()?;
    let v: serde_json::Value = serde_json::from_str(&raw).ok()?;
    if v["username"].as_str()? != username {
        return None;
    }
    Some(v["hash"].as_str()?.to_string())
}
