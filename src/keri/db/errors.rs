use thiserror::Error;

#[allow(dead_code)]
#[derive(Debug, Error)]
pub enum DBError {
    #[error("Invalid code: {0}")]
    CoreError(String),

    #[error("I/O Error: {0}")]
    IoError(String),

    #[error("Filer Error: {0}")]
    FilerError(String),

    #[error("Database Error: {0}")]
    DatabaseError(String),

    #[error("Key Error: {0}")]
    KeyError(String),

    #[error("Value error: {0}")]
    ValueError(String),

    #[error("Parse error: {0}")]
    ParseError(String),

    #[error("Environment error: {0}")]
    EnvError(#[from] heed::Error),

    #[error("Path error: {0}")]
    PathError(String),

    #[error("Operation on closed database")]
    DbClosed,

    #[error("Mapping Error")]
    MapDBError,

    #[error("Missing entry error")]
    MissingEntryError(String),

    #[error("Encoding error")]
    EncodingError(String),
}
