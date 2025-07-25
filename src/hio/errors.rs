use thiserror::Error;

#[allow(dead_code)]
#[derive(Debug, Error)]
pub enum HioError {
    #[error("Hio Error: {0}")]
    HioError(String),

    #[error("Hio Error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Hio Error: {0}")]
    FilerError(String),

    #[error("Hio Error: {0}")]
    SerializationError(String),
}
