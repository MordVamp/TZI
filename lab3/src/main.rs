//! Лабораторная работа №3 — Криптографические алгоритмы
//! Основана на библиотеке CryptoCore (https://github.com/MordVamp/Cryptocore-)
//!
//! Реализованы (из CryptoCore, нужные модули):
//!   - AES-128 (src/core/crypto/aes.rs)
//!   - Режимы: CBC, CFB, OFB, CTR, GCM (src/core/crypto/modes/)
//!   - Хеш-функции: SHA-256, SHA3-256 (src/core/crypto/hash/)
//!   - MAC: HMAC-SHA256, AES-CMAC (src/core/crypto/mac/)
//!   - KDF: PBKDF2 (src/core/crypto/kdf.rs)

mod core;
mod error;

use core::crypto::modes::cbc::CbcMode;
use core::crypto::hash::sha256::Sha256;
use core::crypto::traits::Cipher;

fn main() {
    println!("=== Лабораторная работа №3: Криптографические алгоритмы ===");
    println!("Использует модули из CryptoCore (github.com/MordVamp/Cryptocore-)");
    println!();

    // Демонстрация AES-128-CBC
    let key = b"0123456789abcdef"; // 16 байт
    let iv  = b"abcdef0123456789"; // 16 байт
    let plaintext = b"Hello, CryptoCore!";

    println!("Исходный текст: {:?}", std::str::from_utf8(plaintext).unwrap());

    match CbcMode::new(key, iv) {
        Ok(cipher) => {
            match cipher.encrypt(plaintext) {
                Ok(ct) => {
                    println!("AES-128-CBC зашифровано: {}", hex::encode(&ct));
                    match cipher.decrypt(&ct) {
                        Ok(pt) => println!("Расшифровано: {:?}", std::str::from_utf8(&pt).unwrap_or("err")),
                        Err(e) => println!("Ошибка расшифровки: {}", e),
                    }
                }
                Err(e) => println!("Ошибка шифрования: {}", e),
            }
        }
        Err(e) => println!("Ошибка инициализации CBC: {}", e),
    }

    // Демонстрация SHA-256
    let hasher = Sha256::new();
    let hash = hasher.hash(b"test message");
    println!();
    println!("SHA-256(\"test message\"): {}", hex::encode(&hash));
}
