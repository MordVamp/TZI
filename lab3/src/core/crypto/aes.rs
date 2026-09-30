use super::traits::Cipher;
use crate::error::{CryptoCoreError, Result};
use aes::Aes128;
use cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use cipher::generic_array::GenericArray;

pub struct AesCipher {
    pub cipher: Aes128,
}

impl AesCipher {
    pub fn new(key: &[u8]) -> Result<Self> {
        if key.len() != 16 {
            return Err(CryptoCoreError::InvalidKey(
                "AES-128 requires exactly 16 bytes key".to_string(),
            ));
        }

        let key_array = GenericArray::from_slice(key);
        let cipher = Aes128::new(key_array);
        Ok(AesCipher { cipher })
    }

    // Single block encryption (for CMAC)
    pub fn encrypt_block(&self, block: &[u8; 16]) -> Result<[u8; 16]> {
        let mut generic_block = GenericArray::clone_from_slice(block);
        self.cipher.encrypt_block(&mut generic_block);
        let mut result = [0u8; 16];
        result.copy_from_slice(generic_block.as_slice());
        Ok(result)
    }

    // Single block decryption
    pub fn decrypt_block(&self, block: &[u8; 16]) -> Result<[u8; 16]> {
        let mut generic_block = GenericArray::clone_from_slice(block);
        self.cipher.decrypt_block(&mut generic_block);
        let mut result = [0u8; 16];
        result.copy_from_slice(generic_block.as_slice());
        Ok(result)
    }
}

impl Cipher for AesCipher {
    fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        let block_size = self.block_size();
        let padded_data = self.pad_data(data, block_size)?;
        let mut result = Vec::with_capacity(padded_data.len());
        
        for chunk in padded_data.chunks(block_size) {
            let mut block = GenericArray::clone_from_slice(chunk);
            self.cipher.encrypt_block(&mut block);
            result.extend_from_slice(&block);
        }
        
        Ok(result)
    }

    fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        if data.len() % self.block_size() != 0 {
            return Err(CryptoCoreError::Crypto(
                "Ciphertext length must be a multiple of block size".to_string(),
            ));
        }

        let mut result = Vec::with_capacity(data.len());
        
        for chunk in data.chunks(self.block_size()) {
            let mut block = GenericArray::clone_from_slice(chunk);
            self.cipher.decrypt_block(&mut block);
            result.extend_from_slice(&block);
        }
        
        self.unpad_data(&result)
    }

    fn block_size(&self) -> usize {
        16
    }
}

impl AesCipher {
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