// cmac.rs - Fixed version
use crate::core::crypto::aes::AesCipher;
use crate::error::{CryptoCoreError, Result};

const BLOCK_SIZE: usize = 16;

pub struct Cmac {
    cipher: AesCipher,
    k1: [u8; 16],
    k2: [u8; 16],
    buffer: Vec<u8>,
}

impl Cmac {
    pub fn new(key: &[u8]) -> Result<Self> {
        if key.len() != 16 {
            return Err(CryptoCoreError::InvalidArgument(
                "AES-CMAC requires exactly 16-byte key".to_string()
            ));
        }
        
        let cipher = AesCipher::new(key)?;
        
        // Generate subkeys
        let zero = [0u8; 16];
        let l = cipher.encrypt_block(&zero)?;
        let (k1, k2) = Self::generate_subkeys(&l);
        
        Ok(Self {
            cipher,
            k1,
            k2,
            buffer: Vec::new(),
        })
    }
    
    fn generate_subkeys(l: &[u8; 16]) -> ([u8; 16], [u8; 16]) {
        let mut k1 = [0u8; 16];
        let mut k2 = [0u8; 16];
        
        // Generate K1 by left shifting L
        let mut carry = 0u16;
        for i in (0..16).rev() {
            let val = (l[i] as u16) << 1 | carry;
            k1[i] = (val & 0xFF) as u8;
            carry = val >> 8;
        }
        if (l[0] & 0x80) != 0 {
            k1[15] ^= 0x87;
        }
        
        // Generate K2 by left shifting K1
        carry = 0u16;
        for i in (0..16).rev() {
            let val = (k1[i] as u16) << 1 | carry;
            k2[i] = (val & 0xFF) as u8;
            carry = val >> 8;
        }
        if (k1[0] & 0x80) != 0 {
            k2[15] ^= 0x87;
        }
        
        (k1, k2)
    }
    
    pub fn update(&mut self, data: &[u8]) {
        self.buffer.extend_from_slice(data);
    }
    
    pub fn finalize(mut self) -> Result<[u8; 16]> {
        let message_len = self.buffer.len();
        let is_complete_block = message_len % BLOCK_SIZE == 0;
        
        // Handle padding
        if message_len == 0 {
            // Empty message: pad with 0x80 followed by zeros
            let mut padded = vec![0u8; BLOCK_SIZE];
            padded[0] = 0x80;
            
            // For empty message, we XOR with K2
            let mut block = [0u8; 16];
            for i in 0..16 {
                block[i] = padded[i] ^ self.k2[i];
            }
            
            // Encrypt the block
            self.cipher.encrypt_block(&block)
        } else if !is_complete_block {
            // Incomplete block: pad with 0x80 followed by zeros
            let pad_len = BLOCK_SIZE - (message_len % BLOCK_SIZE);
            self.buffer.push(0x80);
            self.buffer.extend(std::iter::repeat(0u8).take(pad_len - 1));
            
            // Process padded message with K2
            self.process_cbc(&self.k2)
        } else {
            // Complete block(s): use K1
            self.process_cbc(&self.k1)
        }
    }
    
    fn process_cbc(&self, subkey: &[u8; 16]) -> Result<[u8; 16]> {
        let mut state = [0u8; 16];
        let blocks = self.buffer.chunks_exact(BLOCK_SIZE);
        
        for (i, block) in blocks.enumerate() {
            let mut block_array = [0u8; 16];
            block_array.copy_from_slice(block);
            
            // XOR with previous state
            for j in 0..16 {
                block_array[j] ^= state[j];
            }
            
            // For the last block, XOR with subkey
            if i == self.buffer.len() / BLOCK_SIZE - 1 {
                for j in 0..16 {
                    block_array[j] ^= subkey[j];
                }
            }
            
            // Encrypt to get next state
            state = self.cipher.encrypt_block(&block_array)?;
        }
        
        Ok(state)
    }
    
    pub fn compute(key: &[u8], message: &[u8]) -> Result<[u8; 16]> {
        let mut cmac = Self::new(key)?;
        cmac.update(message);
        cmac.finalize()
    }
    
    pub fn compute_file(key: &[u8], path: &std::path::Path) -> Result<[u8; 16]> {
        use std::fs::File;
        use std::io::Read;
        
        let mut cmac = Self::new(key)?;
        let mut file = File::open(path)
            .map_err(|e| CryptoCoreError::FileError(format!("Failed to open file: {}", e)))?;
        
        let mut buffer = [0u8; 4096];
        loop {
            let n = file.read(&mut buffer)
                .map_err(|e| CryptoCoreError::FileError(format!("Failed to read file: {}", e)))?;
            if n == 0 {
                break;
            }
            cmac.update(&buffer[..n]);
        }
        
        cmac.finalize()
    }
    
    pub fn verify(key: &[u8], message: &[u8], expected_cmac: &[u8]) -> Result<bool> {
        let computed = Self::compute(key, message)?;
        Ok(computed.as_slice() == expected_cmac)
    }
    
    pub fn verify_file(key: &[u8], path: &std::path::Path, expected_cmac: &[u8]) -> Result<bool> {
        let computed = Self::compute_file(key, path)?;
        Ok(computed.as_slice() == expected_cmac)
    }
}