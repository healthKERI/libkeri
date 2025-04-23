//! KERI (Key Event Receipt Infrastructure) library implementation in Rust.

// Error handling module
mod errors;

// Re-export Error type
pub use crate::errors::Error;

mod cesr;
mod keri;

pub use crate::cesr::Matter;

/// Initialize the KERI library
pub fn init() -> Result<(), Error> {
    // Initialize sodiumoxide
    if let Err(_) = sodiumoxide::init() {
        return Err(Error::CryptographicError(
            "Failed to initialize sodiumoxide".into(),
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_init() {
        assert!(init().is_ok());
    }
}
