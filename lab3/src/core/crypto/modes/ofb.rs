use crate::core::crypto::aes::AesCipher;
use crate::core::crypto::traits::Cipher;
use crate::error::{CryptoCoreError, Result};
use cipher::{BlockEncrypt};
use cipher::generic_array::GenericArray;

pub struct OfbMode {
    cipher: AesCipher,
    iv: [u8; 16],
}

impl OfbMode {
    pub fn new(key: &[u8], iv: &[u8]) -> Result<Self> {
        if iv.len() != 16 {
            return Err(CryptoCoreError::InvalidArgument(
                "IV must be 16 bytes for OFB mode".to_string()
            ));
        }

        let mut iv_array = [0u8; 16];
        iv_array.copy_from_slice(iv);

        Ok(Self {
            cipher: AesCipher::new(key)?,
            iv: iv_array,
        })
    }
}

impl Cipher for OfbMode {
    fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        let mut result = Vec::with_capacity(data.len());
        let mut keystream = self.iv;

        for chunk in data.chunks(16) {
            // Generate keystream block
            let mut keystream_block = GenericArray::from(keystream);
            self.cipher.cipher.encrypt_block(&mut keystream_block);
            keystream = keystream_block.into();
            
            // XOR plaintext with keystream
            let mut output_block = vec![0u8; chunk.len()];
            for i in 0..chunk.len() {
                output_block[i] = chunk[i] ^ keystream[i];
            }
            
            result.extend_from_slice(&output_block);
        }

        Ok(result)
    }

    fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        // OFB decryption is identical to encryption
        self.encrypt(data)
    }

    fn block_size(&self) -> usize {
        16
    }

    fn requires_padding(&self) -> bool {
        false
    }
}