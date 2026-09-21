use aes::Aes256;
use cbc::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit, block_padding::Pkcs7};
use rand::RngCore;
use sha2::{Digest, Sha256};

type Enc = cbc::Encryptor<Aes256>;
type Dec = cbc::Decryptor<Aes256>;

/// Вывести 32-байтовый ключ из произвольной строки (пароль/лицензия)
pub fn derive_key(secret: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(secret.as_bytes());
    h.finalize().into()
}

/// Зашифровать данные AES-256-CBC.
/// Формат: [16 байт IV][зашифрованные данные]
pub fn encrypt(plaintext: &[u8], key: &[u8; 32]) -> Vec<u8> {
    let mut iv = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut iv);
    let enc = Enc::new(key.into(), &iv.into());
    let mut buf = vec![0u8; plaintext.len() + 16];
    buf[..plaintext.len()].copy_from_slice(plaintext);
    let ct = enc.encrypt_padded_mut::<Pkcs7>(&mut buf, plaintext.len())
        .expect("encrypt");
    let mut out = iv.to_vec();
    out.extend_from_slice(ct);
    out
}

/// Расшифровать данные. Возвращает None при неверном ключе/данных.
pub fn decrypt(data: &[u8], key: &[u8; 32]) -> Option<Vec<u8>> {
    if data.len() < 17 { return None; }
    let (iv, ct) = data.split_at(16);
    let dec = Dec::new(key.into(), iv.into());
    let mut buf = ct.to_vec();
    dec.decrypt_padded_mut::<Pkcs7>(&mut buf).ok().map(|b| b.to_vec())
}
