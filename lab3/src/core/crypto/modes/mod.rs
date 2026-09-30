pub mod cbc;
pub mod cfb;
pub mod ofb;
pub mod ctr;
pub mod gcm;  // Add GCM module

use crate::error::Result;
use super::traits::Cipher;

pub enum BlockMode {
    Cbc(cbc::CbcMode),
    Cfb(cfb::CfbMode),
    Ofb(ofb::OfbMode),
    Ctr(ctr::CtrMode),
    Gcm(gcm::Gcm),  // Add GCM variant
}

impl BlockMode {
    pub fn new(mode_name: &str, key: &[u8], iv: &[u8]) -> Result<Self> {
        match mode_name.to_lowercase().as_str() {
            "cbc" => Ok(Self::Cbc(cbc::CbcMode::new(key, iv)?)),
            "cfb" => Ok(Self::Cfb(cfb::CfbMode::new(key, iv)?)),
            "ofb" => Ok(Self::Ofb(ofb::OfbMode::new(key, iv)?)),
            "ctr" => Ok(Self::Ctr(ctr::CtrMode::new(key, iv)?)),
            "gcm" => {
                // For GCM, iv is the nonce (12 bytes expected)
                if iv.len() != 12 {
                    return Err(crate::error::CryptoCoreError::InvalidArgument(
                        "GCM requires 12-byte nonce".to_string()
                    ));
                }
                Ok(Self::Gcm(gcm::Gcm::new(key)?))
            }
            _ => Err(crate::error::CryptoCoreError::InvalidArgument(
                format!("Unsupported mode: {}", mode_name)
            )),
        }
    }
}

// Implement Cipher trait for BlockMode
impl Cipher for BlockMode {
    fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        match self {
            Self::Cbc(cipher) => cipher.encrypt(data),
            Self::Cfb(cipher) => cipher.encrypt(data),
            Self::Ofb(cipher) => cipher.encrypt(data),
            Self::Ctr(cipher) => cipher.encrypt(data),
            Self::Gcm(_) => {
                // GCM requires AAD - will be handled differently
                Err(crate::error::CryptoCoreError::InvalidArgument(
                    "GCM encryption requires AAD parameter".to_string()
                ))
            }
        }
    }

    fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        match self {
            Self::Cbc(cipher) => cipher.decrypt(data),
            Self::Cfb(cipher) => cipher.decrypt(data),
            Self::Ofb(cipher) => cipher.decrypt(data),
            Self::Ctr(cipher) => cipher.decrypt(data),
            Self::Gcm(_) => {
                // GCM requires AAD and tag - will be handled differently
                Err(crate::error::CryptoCoreError::InvalidArgument(
                    "GCM decryption requires AAD and tag parameters".to_string()
                ))
            }
        }
    }

    fn block_size(&self) -> usize {
        16
    }

    fn requires_padding(&self) -> bool {
        match self {
            Self::Cbc(_) => true,
            Self::Cfb(_) | Self::Ofb(_) | Self::Ctr(_) | Self::Gcm(_) => false,
        }
    }
}

// AEAD-specific methods for GCM
impl BlockMode {
    pub fn encrypt_with_aad(&self, data: &[u8], aad: &[u8], nonce: &[u8]) -> Result<Vec<u8>> {
        match self {
            Self::Gcm(gcm) => {
                let (ciphertext, tag) = gcm.encrypt(data, aad, nonce)?;
                // Return format: ciphertext || tag
                let mut result = ciphertext;
                result.extend_from_slice(&tag);
                Ok(result)
            }
            _ => Err(crate::error::CryptoCoreError::InvalidArgument(
                "AEAD operations only supported for GCM mode".to_string()
            )),
        }
    }
    
    pub fn decrypt_with_aad(&self, data: &[u8], aad: &[u8], nonce: &[u8]) -> Result<Vec<u8>> {
        match self {
            Self::Gcm(gcm) => {
                if data.len() < 16 {
                    return Err(crate::error::CryptoCoreError::InvalidArgument(
                        "Data too short to contain tag".to_string()
                    ));
                }
                let ciphertext_len = data.len() - 16;
                let ciphertext = &data[..ciphertext_len];
                let tag = &data[ciphertext_len..];
                
                gcm.decrypt(ciphertext, aad, nonce, tag)
            }
            _ => Err(crate::error::CryptoCoreError::InvalidArgument(
                "AEAD operations only supported for GCM mode".to_string()
            )),
        }
    }
}