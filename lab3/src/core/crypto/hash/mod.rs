pub mod sha256;
pub mod sha3_256;
pub use sha256::Sha256;
use crate::error::Result;

pub enum HashAlgorithm {
    Sha256,
    Sha3_256,
}

impl HashAlgorithm {
    pub fn from_str(name: &str) -> Result<Self> {
        match name.to_lowercase().as_str() {
            "sha256" => Ok(Self::Sha256),
            "sha3-256" => Ok(Self::Sha3_256),
            _ => Err(crate::error::CryptoCoreError::InvalidArgument(
                format!("Unsupported hash algorithm: {}", name)
            )),
        }
    }

    pub fn compute_hash(&self, data: &[u8]) -> Result<String> {
        match self {
            Self::Sha256 => {
                let mut hasher = sha256::Sha256::new();
                hasher.update(data);
                let result = hasher.finalize();
                Ok(hex::encode(result))
            }
            Self::Sha3_256 => {
                let mut hasher = sha3_256::Sha3_256::new();
                hasher.update(data);
                let result = hasher.finalize();
                Ok(hex::encode(result))
            }
        }
    }

    pub fn compute_file_hash(&self, path: &std::path::Path) -> Result<String> {
        use std::fs::File;
        use std::io::Read;
        
        let mut file = File::open(path)
            .map_err(|e| crate::error::CryptoCoreError::FileError(format!("Failed to open file: {}", e)))?;
        
        let hasher = match self {
            Self::Sha256 => {
                let mut h = sha256::Sha256::new();
                let mut buffer = [0u8; 4096];
                loop {
                    let n = file.read(&mut buffer)
                        .map_err(|e| crate::error::CryptoCoreError::FileError(format!("Failed to read file: {}", e)))?;
                    if n == 0 { break; }
                    h.update(&buffer[..n]);
                }
                h.finalize()
            }
            Self::Sha3_256 => {
                let mut h = sha3_256::Sha3_256::new();
                let mut buffer = [0u8; 4096];
                loop {
                    let n = file.read(&mut buffer)
                        .map_err(|e| crate::error::CryptoCoreError::FileError(format!("Failed to read file: {}", e)))?;
                    if n == 0 { break; }
                    h.update(&buffer[..n]);
                }
                h.finalize()
            }
        };
        
        Ok(hex::encode(hasher))
    }
}