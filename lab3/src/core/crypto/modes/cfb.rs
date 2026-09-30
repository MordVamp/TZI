use crate::core::crypto::aes::AesCipher;
use crate::core::crypto::traits::Cipher;
use crate::error::{CryptoCoreError, Result};
use cipher::{BlockEncrypt};
use cipher::generic_array::GenericArray;

pub struct CfbMode {
    cipher: AesCipher,
    iv: [u8; 16],
}

impl CfbMode {
    pub fn new(key: &[u8], iv: &[u8]) -> Result<Self> {
        if iv.len() != 16 {
            return Err(CryptoCoreError::InvalidArgument(
                "IV must be 16 bytes for CFB mode".to_string()
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

impl Cipher for CfbMode {
    fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        let mut result = Vec::with_capacity(data.len());
        let mut feedback = self.iv;

        for chunk in data.chunks(16) {
            // Encrypt the feedback register
            let mut feedback_block = GenericArray::from(feedback);
            self.cipher.cipher.encrypt_block(&mut feedback_block);
            let encrypted_feedback = feedback_block.as_slice();
            
            // XOR plaintext with encrypted feedback
            let mut output_block = vec![0u8; chunk.len()];
            for i in 0..chunk.len() {
                output_block[i] = chunk[i] ^ encrypted_feedback[i];
            }
            
            result.extend_from_slice(&output_block);
            
            // Update feedback register - for full block CFB
            if chunk.len() == 16 {
                feedback.copy_from_slice(&output_block);
            } else {
                // For partial blocks, shift and keep the rest
                let mut new_feedback = [0u8; 16];
                new_feedback[..chunk.len()].copy_from_slice(&output_block);
                feedback = new_feedback;
            }
        }

        Ok(result)
    }

    fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        let mut result = Vec::with_capacity(data.len());
        let mut feedback = self.iv;

        for chunk in data.chunks(16) {
            // Encrypt the feedback register
            let mut feedback_block = GenericArray::from(feedback);
            self.cipher.cipher.encrypt_block(&mut feedback_block);
            let encrypted_feedback = feedback_block.as_slice();
            
            // XOR ciphertext with encrypted feedback
            let mut output_block = vec![0u8; chunk.len()];
            for i in 0..chunk.len() {
                output_block[i] = chunk[i] ^ encrypted_feedback[i];
            }
            
            result.extend_from_slice(&output_block);
            
            // Update feedback register with ciphertext (not output)
            if chunk.len() == 16 {
                feedback.copy_from_slice(chunk);
            } else {
                let mut new_feedback = [0u8; 16];
                new_feedback[..chunk.len()].copy_from_slice(chunk);
                feedback = new_feedback;
            }
        }

        Ok(result)
    }

    fn block_size(&self) -> usize {
        16
    }

    fn requires_padding(&self) -> bool {
        false
    }
}