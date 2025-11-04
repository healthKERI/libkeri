//! KERI (Key Event Receipt Infrastructure) library implementation in Rust.

// Error handling module
mod errors;

// Re-export Error type
pub use crate::errors::Error;

mod cesr;
mod hio;
pub mod keri;

pub use crate::cesr::Matter;
pub use crate::cesr::Tiers;
pub use crate::cesr::tholder::{Tholder, TholderSith};

// Errors
pub use crate::keri::KERIError;

// Database layer
pub use crate::keri::db::dbing::LMDBer;
pub use crate::keri::db::basing::{Baser, HabitatRecord, KeyStateRecord};

// Application layer - keeping
pub use crate::keri::app::keeping::{Keeper, Manager};
pub use crate::keri::app::keeping::creators::Algos;

// Application layer - habbing
pub use crate::keri::app::habbing::{BaseHab, Hab};
pub use crate::keri::app::configing::Configer;

// Core - eventing
pub use crate::keri::core::eventing::kevery::Kevery;
pub use crate::keri::core::eventing::kever::Kever;

// Core - routing
pub use crate::keri::core::routing::{Revery, Router};

// Core - serdering
pub use crate::keri::core::serdering::SadValue;

// Core - parsing
pub use crate::keri::core::parsing::{Parser, Handlers, Message, MessageHandler};

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
