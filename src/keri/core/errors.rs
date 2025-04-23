use thiserror::Error;

#[allow(dead_code)]
#[derive(Debug, Error)]
pub enum CoreError {
    #[error("Invalid code: {0}")]
    InvalidCode(String),

    #[error("Invalid code: {0}")]
    NotRelativePath(String),

    #[error("Invalid code: {0}")]
    IoError(String),

    #[error("Invalid code: {0}")]
    OtherError(String),

    #[error("Invalid code: {0}")]
    PermissionError(String),

    #[error("Invalid code: {0}")]
    FilerError(String),
}
