use thiserror::Error;

#[derive(Error, Debug)]
pub enum CryptoCoreError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    
    #[error("Crypto error: {0}")]
    Crypto(String),
    
    #[error("Invalid key: {0}")]
    InvalidKey(String),
    
    #[error("Invalid argument: {0}")]
    InvalidArgument(String),
    
    #[error("File error: {0}")]
    FileError(String),
    
    #[error("Padding error: {0}")]
    PaddingError(String),
    
    #[error("Configuration error: {0}")]
    ConfigError(String),
    
    #[error("Hex decoding error: {0}")]
    HexError(#[from] hex::FromHexError),
}

pub type Result<T> = std::result::Result<T, CryptoCoreError>;