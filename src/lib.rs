//! KERI (Key Event Receipt Infrastructure) library implementation in Rust.

// Error handling module
mod errors;

// Re-export Error type
pub use crate::errors::Error;

mod cesr;
mod hio;
pub mod keri;

pub use crate::cesr::Matter;

// Re-export commonly used types for easier access
pub use crate::keri::db::dbing::LMDBer;
pub use crate::keri::db::basing::Baser;
pub use crate::keri::app::keeping::{Keeper, Manager};

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
