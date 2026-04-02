//! KERI (Key Event Receipt Infrastructure) library implementation in Rust.

// Error handling module
mod errors;

// Re-export Error type
pub use crate::errors::Error;

mod cesr;
mod hio;
pub mod keri;

pub use crate::cesr::tholder::{Tholder, TholderSith};
pub use crate::cesr::Matter;
pub use crate::cesr::Tiers;

// Errors
pub use crate::keri::KERIError;

// Database layer
pub use crate::keri::db::basing::{Baser, HabitatRecord, KeyStateRecord};
pub use crate::keri::db::dbing::LMDBer;

// Application layer - keeping
pub use crate::keri::app::keeping::creators::Algos;
pub use crate::keri::app::keeping::{Keeper, Manager};

// Application layer - habbing
pub use crate::keri::app::configing::Configer;
pub use crate::keri::app::habbing::{BaseHab, Hab};

// Core - eventing
pub use crate::keri::core::eventing::kever::Kever;
pub use crate::keri::core::eventing::kevery::Kevery;

// Core - routing
pub use crate::keri::core::routing::{Revery, Router};

// Core - serdering
pub use crate::keri::core::serdering::SadValue;
pub use crate::keri::core::serdering::{Rawifiable, Sadder, Serder, SerderKERI, Serdery};

// Core - eventing (builders and message assembly)
pub use crate::keri::core::eventing::incept::InceptionEventBuilder;
pub use crate::keri::core::eventing::messagize;
pub use crate::keri::core::eventing::receipt::ReceiptEventBuilder;

// Core - parsing
pub use crate::keri::core::parsing::{Handlers, Message, MessageHandler, Parser};

// Re-export commonly used types for easier access
pub use crate::keri::app::keeping::{Keeper, Manager};
pub use crate::keri::db::basing::Baser;
pub use crate::keri::db::dbing::LMDBer;
// CESR primitives
pub use crate::cesr::cigar::Cigar;
pub use crate::cesr::diger::Diger;
pub use crate::cesr::indexing::siger::Siger;
pub use crate::cesr::signing::{Salter, Sigmat, Signer};
pub use crate::cesr::verfer::Verfer;

// KERI constants
pub use crate::keri::Ilks;

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
