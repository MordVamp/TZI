use crate::error::Result;

pub trait Cipher {
    fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>>;
    fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>>;
    fn block_size(&self) -> usize;
    fn requires_padding(&self) -> bool {
        true
    }
}

//  AEAD extension trait
pub trait AeadCipher: Cipher {
    fn encrypt_with_aad(&self, data: &[u8], aad: &[u8], nonce: &[u8]) -> Result<(Vec<u8>, Vec<u8>)>;
    fn decrypt_with_aad(&self, ciphertext: &[u8], aad: &[u8], nonce: &[u8], tag: &[u8]) -> Result<Vec<u8>>;
    fn nonce_size(&self) -> usize;
    fn tag_size(&self) -> usize;
}