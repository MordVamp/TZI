pub mod hmac;
pub mod cmac;

pub use hmac::Hmac;
pub use cmac::Cmac;


use crate::error::Result;

pub enum MacAlgorithm {
    Hmac,
    Cmac,
}

impl MacAlgorithm {
    pub fn from_str(name: &str) -> Result<Self> {
        match name.to_lowercase().as_str() {
            "hmac" => Ok(Self::Hmac),
            "cmac" => Ok(Self::Cmac),
            _ => Err(crate::error::CryptoCoreError::InvalidArgument(
                format!("Unsupported MAC algorithm: {}", name)
            )),
        }
    }
}

// Unified MAC interface
pub struct Mac {
    algorithm: MacAlgorithm,
    key: Vec<u8>,
}

impl Mac {
    pub fn new(algorithm: &str, key: &[u8]) -> Result<Self> {
        let algorithm = MacAlgorithm::from_str(algorithm)?;
        Ok(Self {
            algorithm,
            key: key.to_vec(),
        })
    }
    
    pub fn compute(&self, message: &[u8]) -> Result<Vec<u8>> {
        match &self.algorithm {
            MacAlgorithm::Hmac => {
                let result = Hmac::compute(&self.key, message);
                Ok(result.to_vec())
            }
            MacAlgorithm::Cmac => {
                let result = Cmac::compute(&self.key, message)?;
                Ok(result.to_vec())
            }
        }
    }
    
    pub fn compute_file(&self, path: &std::path::Path) -> Result<Vec<u8>> {
        match &self.algorithm {
            MacAlgorithm::Hmac => {
                let result = Hmac::compute_file(&self.key, path)?;
                Ok(result.to_vec())
            }
            MacAlgorithm::Cmac => {
                let result = Cmac::compute_file(&self.key, path)?;
                Ok(result.to_vec())
            }
        }
    }
    
    pub fn verify(&self, message: &[u8], expected_mac: &[u8]) -> Result<bool> {
        match &self.algorithm {
            MacAlgorithm::Hmac => {
                Ok(Hmac::verify(&self.key, message, expected_mac))
            }
            MacAlgorithm::Cmac => {
                Cmac::verify(&self.key, message, expected_mac)
            }
        }
    }
    
    pub fn verify_file(&self, path: &std::path::Path, expected_mac: &[u8]) -> Result<bool> {
        match &self.algorithm {
            MacAlgorithm::Hmac => {
                Hmac::verify_file(&self.key, path, expected_mac)
            }
            MacAlgorithm::Cmac => {
                Cmac::verify_file(&self.key, path, expected_mac)
            }
        }
    }
}