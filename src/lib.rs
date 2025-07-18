//! KERI (Key Event Receipt Infrastructure) library implementation in Rust.

// Error handling module
mod errors;

// Re-export Error type
pub use crate::errors::Error;

mod cesr;
mod keri;

// Core CESR exports for witness functionality
pub use crate::cesr::Matter;
pub use crate::cesr::signing::{Salter, Signer};
pub use crate::cesr::verfer::Verfer;
pub use crate::cesr::indexing::siger::Siger;
pub use crate::cesr::cigar::Cigar;

// Core KERI exports for witness functionality
pub use crate::keri::{KERIError, Ilks};
pub use crate::keri::core::eventing::InceptionEventBuilder;
pub use crate::keri::core::eventing::receipt::ReceiptEventBuilder;
pub use crate::keri::core::eventing::kever::KeverBuilder;
pub use crate::keri::core::eventing::messagize;
pub use crate::keri::core::serdering::{SerderKERI, Serder, Rawifiable};
pub use crate::keri::app::keeping::{Manager, Keeper};
pub use crate::keri::app::configing::{Configer, ConfigFormat};
pub use crate::keri::db::dbing::LMDBer;
pub use crate::keri::db::dbing::keys::{dg_key, sn_key};
pub use crate::keri::db::basing::Baser;

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
