use crate::core::crypto::aes::AesCipher;
use crate::core::crypto::traits::Cipher;
use crate::error::{CryptoCoreError, Result};
use cipher::{BlockDecrypt, BlockEncrypt};
use cipher::generic_array::GenericArray;

pub struct CbcMode {
    cipher: AesCipher,
    iv: [u8; 16],
}

impl CbcMode {
    pub fn new(key: &[u8], iv: &[u8]) -> Result<Self> {
        if iv.len() != 16 {
            return Err(CryptoCoreError::InvalidArgument(
                "IV must be 16 bytes for CBC mode".to_string()
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

impl Cipher for CbcMode {
    fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        let block_size = self.block_size();
        let padded_data = if self.requires_padding() {
            self.pad_data(data, block_size)?
        } else {
            data.to_vec()
        };

        let mut result = Vec::with_capacity(padded_data.len());
        let mut previous_block = self.iv;

        for chunk in padded_data.chunks(block_size) {
            let mut block = [0u8; 16];
            block.copy_from_slice(chunk);

            // XOR with previous ciphertext block (or IV for first block)
            for i in 0..block_size {
                block[i] ^= previous_block[i];
            }

            // Encrypt the block
            let mut generic_block = GenericArray::from(block);
            self.cipher.cipher.encrypt_block(&mut generic_block);
            let encrypted_block = generic_block.as_slice().to_vec();

            result.extend_from_slice(&encrypted_block);
            previous_block.copy_from_slice(&encrypted_block);
        }

        Ok(result)
    }

    fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        if data.len() % self.block_size() != 0 {
            return Err(CryptoCoreError::Crypto(
                "Ciphertext length must be a multiple of block size".to_string()
            ));
        }

        let mut result = Vec::with_capacity(data.len());
        let mut previous_block = self.iv;

        for chunk in data.chunks(self.block_size()) {
            let mut block = [0u8; 16];
            block.copy_from_slice(chunk);

            // Decrypt the block
            let mut generic_block = GenericArray::from(block);
            self.cipher.cipher.decrypt_block(&mut generic_block);
            let mut decrypted_block = [0u8; 16];
            decrypted_block.copy_from_slice(generic_block.as_slice());

            // XOR with previous ciphertext block (or IV for first block)
            let mut plaintext_block = vec![0u8; self.block_size()];
            for i in 0..self.block_size() {
                plaintext_block[i] = decrypted_block[i] ^ previous_block[i];
            }

            result.extend_from_slice(&plaintext_block);
            previous_block.copy_from_slice(chunk);
        }

        if self.requires_padding() {
            self.unpad_data(&result)
        } else {
            Ok(result)
        }
    }

    fn block_size(&self) -> usize {
        16
    }

    fn requires_padding(&self) -> bool {
        true
    }
}

impl CbcMode {
    fn pad_data(&self, data: &[u8], block_size: usize) -> Result<Vec<u8>> {
        let mut padded = data.to_vec();
        let pad_len = block_size - (data.len() % block_size);
        padded.extend(std::iter::repeat(pad_len as u8).take(pad_len));
        Ok(padded)
    }

    fn unpad_data(&self, data: &[u8]) -> Result<Vec<u8>> {
        if data.is_empty() {
            return Ok(Vec::new());
        }
        
        let pad_byte = data[data.len() - 1];
        let pad_len = pad_byte as usize;
        
        if pad_len == 0 || pad_len > self.block_size() || data.len() < pad_len {
            return Err(CryptoCoreError::PaddingError("Invalid padding".to_string()));
        }
        
        let mut padding_valid = true;
        for i in (data.len() - pad_len)..data.len() {
            padding_valid &= data[i] == pad_byte;
        }
        
        if !padding_valid {
            return Err(CryptoCoreError::PaddingError("Invalid padding bytes".to_string()));
        }
        
        Ok(data[..data.len() - pad_len].to_vec())
    }
}