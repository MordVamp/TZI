use crate::core::crypto::aes::AesCipher;
use crate::core::crypto::traits::Cipher;
use crate::error::{CryptoCoreError, Result};
use cipher::{BlockEncrypt};
use cipher::generic_array::GenericArray;

pub struct CtrMode {
    cipher: AesCipher,
    nonce: [u8; 16],
}

impl CtrMode {
    pub fn new(key: &[u8], iv: &[u8]) -> Result<Self> {
        if iv.len() != 16 {
            return Err(CryptoCoreError::InvalidArgument(
                "IV must be 16 bytes for CTR mode".to_string()
            ));
        }

        let mut nonce = [0u8; 16];
        nonce.copy_from_slice(iv);

        Ok(Self {
            cipher: AesCipher::new(key)?,
            nonce,
        })
    }
}

impl Cipher for CtrMode {
    fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        let mut result = Vec::with_capacity(data.len());
        let mut counter = u128::from_be_bytes(self.nonce);

        for chunk in data.chunks(16) {
            // Encrypt counter value
            let counter_bytes = counter.to_be_bytes();
            let mut counter_block = GenericArray::from(counter_bytes);
            self.cipher.cipher.encrypt_block(&mut counter_block);
            let encrypted_counter = counter_block.as_slice();
            
            // XOR plaintext with encrypted counter
            let mut output_block = vec![0u8; chunk.len()];
            for i in 0..chunk.len() {
                output_block[i] = chunk[i] ^ encrypted_counter[i];
            }
            
            result.extend_from_slice(&output_block);
            counter = counter.wrapping_add(1);
        }

        Ok(result)
    }

    fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        // CTR decryption is identical to encryption
        self.encrypt(data)
    }

    fn block_size(&self) -> usize {
        16
    }

    fn requires_padding(&self) -> bool {
        false
    }
}