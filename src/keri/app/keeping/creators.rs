use crate::cesr::signing::{Salter, Signer};
use crate::cesr::{mtr_dex, Tiers};
use crate::errors::MatterError;
use crate::Matter;
use std::fmt;
use std::fmt::Debug;

/// Algorithm options for key creation
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Algos {
    Randy,
    Salty,
}

impl fmt::Display for Algos {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Algos::Randy => write!(f, "randy"),
            Algos::Salty => write!(f, "salty"),
        }
    }
}

impl Algos {
    pub fn from_str(s: &str) -> Result<Self, MatterError> {
        match s.to_lowercase().as_str() {
            "randy" => Ok(Algos::Randy),
            "salty" => Ok(Algos::Salty),
            _ => Err(MatterError::ValueError(format!(
                "Unsupported creation algorithm = {}.",
                s
            ))),
        }
    }
}

/// Creator trait defines the interface for key pair creation
pub trait Creator: Debug {
    /// Create signers based on parameters
    fn create(
        &self,
        codes: Option<Vec<&str>>,
        count: Option<usize>,
        code: Option<&str>,
        pidx: Option<usize>,
        ridx: Option<usize>,
        kidx: Option<usize>,
        transferable: Option<bool>,
        temp: Option<bool>,
    ) -> Vec<Signer>;

    /// Get the salt value
    fn salt(&self) -> String;

    /// Get the stem value
    fn stem(&self) -> String;

    /// Get the tier value
    fn tier(&self) -> Option<&Tiers>;
}

/// RandyCreator creates key pairs based on re-randomizing each seed algorithm
#[derive(Debug)]
pub struct RandyCreator {
    // No fields required for base implementation
}

impl RandyCreator {
    /// Create a new RandyCreator instance
    pub fn new() -> Self {
        RandyCreator {}
    }
}

impl Creator for RandyCreator {
    fn create(
        &self,
        codes: Option<Vec<&str>>,
        count: Option<usize>,
        code: Option<&str>,
        _pidx: Option<usize>,
        _ridx: Option<usize>,
        _kidx: Option<usize>,
        transferable: Option<bool>,
        _temp: Option<bool>,
    ) -> Vec<Signer> {
        let count = count.unwrap_or(1);
        let code = code.unwrap_or(mtr_dex::ED25519_SEED);
        let transferable = transferable.unwrap_or(true);

        let mut signers = Vec::new();

        // If codes provided, use them, otherwise create 'count' signers with the same code
        if let Some(code_list) = codes {
            for &c in code_list.iter() {
                signers.push(
                    Signer::new(None, Some(c), Some(transferable))
                        .expect("Failed to create signer"),
                );
            }
        } else {
            for _ in 0..count {
                signers.push(
                    Signer::new(None, Some(code), Some(transferable))
                        .expect("Failed to create signer"),
                );
            }
        }

        signers
    }

    fn salt(&self) -> String {
        String::new()
    }

    fn stem(&self) -> String {
        String::new()
    }

    fn tier(&self) -> Option<&Tiers> {
        None
    }
}

/// SaltyCreator creates key pairs based on random salt plus path stretch algorithm
#[derive(Debug)]
pub struct SaltyCreator {
    salter: Salter,
    stem: String,
}

impl SaltyCreator {
    /// Create a new SaltyCreator
    pub fn new(
        salt: Option<&str>,
        stem: Option<&str>,
        tier: Option<Tiers>,
    ) -> Result<Self, MatterError> {
        let salter = if let Some(s) = salt {
            Salter::from_qb64_and_tier(s, tier)
        } else {
            Salter::new(None, None, tier)
        }?;

        let stem = stem.unwrap_or("").to_string();

        Ok(SaltyCreator { salter, stem })
    }
}

impl Creator for SaltyCreator {
    fn create(
        &self,
        codes: Option<Vec<&str>>,
        count: Option<usize>,
        code: Option<&str>,
        pidx: Option<usize>,
        ridx: Option<usize>,
        kidx: Option<usize>,
        transferable: Option<bool>,
        temp: Option<bool>,
    ) -> Vec<Signer> {
        let count = count.unwrap_or(1);
        let code = code.unwrap_or(mtr_dex::ED25519_SEED);
        let transferable = transferable.unwrap_or(true);

        // Additional parameters with defaults
        let pidx = pidx.unwrap_or(0);
        let ridx = ridx.unwrap_or(0);
        let kidx = kidx.unwrap_or(0);
        let temp = temp.unwrap_or(false);

        self.create_with_options(codes, count, code, pidx, ridx, kidx, transferable, temp)
    }

    fn salt(&self) -> String {
        self.salter.qb64()
    }

    fn stem(&self) -> String {
        self.stem.clone()
    }

    fn tier(&self) -> Option<&Tiers> {
        Some(self.salter.tier())
    }
}

impl SaltyCreator {
    /// Create signers with additional options
    pub fn create_with_options(
        &self,
        codes: Option<Vec<&str>>,
        count: usize,
        code: &str,
        pidx: usize,
        ridx: usize,
        kidx: usize,
        transferable: bool,
        temp: bool,
    ) -> Vec<Signer> {
        let mut signers = Vec::new();

        // Generate code list if not provided
        let code_list = if let Some(codes) = codes {
            codes
        } else {
            vec![code; count]
        };

        // Create stem from provided stem or pidx
        let stem = if !self.stem.is_empty() {
            self.stem.clone()
        } else {
            format!("{:x}", pidx)
        };

        // Create signers for each code
        for (i, &code) in code_list.iter().enumerate() {
            let path = format!("{}{:x}{:x}", stem, ridx, kidx + i);

            // Get tier from salter
            let tier_option = if *self.salter.tier() == Tiers::HIGH {
                Some(&Tiers::HIGH)
            } else if *self.salter.tier() == Tiers::MED {
                Some(&Tiers::MED)
            } else if *self.salter.tier() == Tiers::LOW {
                Some(&Tiers::LOW)
            } else {
                None
            };

            match self
                .salter
                .signer(Some(code), Some(transferable), &path, tier_option, temp)
            {
                Ok(signer) => signers.push(signer),
                Err(e) => {
                    eprintln!("Error creating signer: {:?}", e);
                    // Continue with next signer instead of failing completely
                }
            }
        }

        signers
    }
}

// Default implementations
impl Default for RandyCreator {
    fn default() -> Self {
        Self::new()
    }
}

/// Factory for creating Creator instances based on algorithm choice
#[derive(Debug)]
pub struct Creatory {
    algo: Algos,
}

impl Creatory {
    /// Create a new Creatory with the specified algorithm
    pub fn new(algo: Algos) -> Self {
        Creatory { algo }
    }

    /// Create a Creator instance based on the chosen algorithm
    pub fn make(
        &self,
        salt: Option<&str>,
        stem: Option<&str>,
        tier: Option<Tiers>,
    ) -> Result<Box<dyn Creator>, MatterError> {
        match self.algo {
            Algos::Randy => Ok(Box::new(RandyCreator::new())),
            Algos::Salty => {
                let salty = SaltyCreator::new(salt, stem, tier)?;
                Ok(Box::new(salty))
            }
        }
    }
}

// Alternative implementation with builder pattern for more flexibility
pub struct CreatoryBuilder {
    algo: Algos,
    salt: Option<String>,
    stem: Option<String>,
    tier: Option<Tiers>,
}

impl CreatoryBuilder {
    pub fn new(algo: Algos) -> Self {
        CreatoryBuilder {
            algo,
            salt: None,
            stem: None,
            tier: None,
        }
    }

    pub fn with_salt(mut self, salt: &str) -> Self {
        self.salt = Some(salt.to_string());
        self
    }

    pub fn with_stem(mut self, stem: &str) -> Self {
        self.stem = Some(stem.to_string());
        self
    }

    pub fn with_tier(mut self, tier: Tiers) -> Self {
        self.tier = Some(tier);
        self
    }

    pub fn build(self) -> Result<Box<dyn Creator>, MatterError> {
        match self.algo {
            Algos::Randy => Ok(Box::new(RandyCreator::new())),
            Algos::Salty => {
                let salt_ref = self.salt.as_deref();
                let stem_ref = self.stem.as_deref();
                let tier = self.tier;

                let salty = SaltyCreator::new(salt_ref, stem_ref, tier)?;
                Ok(Box::new(salty))
            }
        }
    }
}

// Default implementations
impl Default for Creatory {
    fn default() -> Self {
        Self::new(Algos::Salty)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cesr::non_trans_dex;
    use crate::Matter;

    #[test]
    fn test_randy_creator() -> Result<(), MatterError> {
        // Test RandyCreator basics
        let creator = RandyCreator::new();

        // Test interface properties
        assert_eq!(creator.salt(), "");
        assert_eq!(creator.stem(), "");
        assert_eq!(creator.tier(), None);

        // Test creating a single default signer
        let signers = creator.create(None, None, None, None, None, None, None, None);
        assert_eq!(signers.len(), 1);

        let signer = &signers[0];
        assert_eq!(signer.code(), mtr_dex::ED25519_SEED);
        assert_eq!(signer.verfer().code(), mtr_dex::ED25519);
        assert!(!non_trans_dex::TUPLE.contains(&signer.verfer().code()));

        // Test creating multiple signers that are non-transferable
        let signers = creator.create(
            None,
            Some(2),
            None,
            None,
            None,
            None,
            Some(false),
            Some(false),
        );
        assert_eq!(signers.len(), 2);

        for signer in &signers {
            assert_eq!(signer.code(), mtr_dex::ED25519_SEED);
            assert_eq!(signer.verfer().code(), mtr_dex::ED25519N);
            assert!(non_trans_dex::TUPLE.contains(&signer.verfer().code()));
        }

        // Test creating signers with specific codes
        let codes = vec![mtr_dex::ED25519_SEED, mtr_dex::ED25519_SEED];
        let signers = creator.create(Some(codes), None, None, None, None, None, None, None);
        assert_eq!(signers.len(), 2);

        for signer in &signers {
            assert_eq!(signer.code(), mtr_dex::ED25519_SEED);
            assert_eq!(signer.verfer().code(), mtr_dex::ED25519);
        }

        Ok(())
    }

    #[test]
    fn test_salty_creator() -> Result<(), MatterError> {
        // Test SaltyCreator with default parameters
        let creator = SaltyCreator::new(None, None, None)?;

        // Check basic properties
        assert!(!creator.salt().is_empty()); // Should have a random salt
        assert_eq!(creator.stem(), "");
        assert_eq!(creator.tier(), Some(&Tiers::LOW)); // Default tier

        // Check salter properties
        assert_eq!(creator.salter.code(), mtr_dex::SALT_128);

        // Test creating a single default signer
        let signers = creator.create(None, None, None, None, None, None, None, None);
        assert_eq!(signers.len(), 1);

        let signer = &signers[0];
        assert_eq!(signer.code(), mtr_dex::ED25519_SEED);
        assert_eq!(signer.verfer().code(), mtr_dex::ED25519);
        assert!(!non_trans_dex::TUPLE.contains(&signer.verfer().code()));

        // Test creating multiple signers that are non-transferable
        let signers = creator.create(
            None,
            Some(2),
            None,
            None,
            None,
            None,
            Some(false),
            Some(false),
        );
        assert_eq!(signers.len(), 2);
        assert_eq!(signers.len(), 2);

        for signer in &signers {
            assert_eq!(signer.code(), mtr_dex::ED25519_SEED);
            assert_eq!(signer.verfer().code(), mtr_dex::ED25519N);
            assert!(non_trans_dex::TUPLE.contains(&signer.verfer().code()));
        }

        // Test with specific salt
        let raw = b"0123456789abcdef";
        let salt = Salter::new(Some(raw), None, None)?.qb64();
        assert_eq!(salt, "0AAwMTIzNDU2Nzg5YWJjZGVm");

        let creator = SaltyCreator::new(Some(&salt), None, None)?;
        assert_eq!(creator.salt(), salt);
        assert_eq!(creator.salter.raw(), raw);

        // Test creating a deterministic signer
        let signers = creator.create(None, None, None, None, None, None, None, None);
        assert_eq!(signers.len(), 1);

        let signer = &signers[0];
        assert_eq!(signer.code(), mtr_dex::ED25519_SEED);
        assert_eq!(
            signer.qb64(),
            "APMJe0lwOpwnX9PkvX1mh26vlzGYl6RWgWGclc8CAQJ9"
        );
        assert_eq!(signer.verfer().code(), mtr_dex::ED25519);
        assert!(!non_trans_dex::TUPLE.contains(&signer.verfer().code()));
        assert_eq!(
            signer.verfer().qb64(),
            "DMZy6qbgnKzvCE594tQ4SPs6pIECXTYQBH7BkC4hNY3E"
        );

        // Test creating a non-transferable temporary signer
        let signers =
            creator.create_with_options(None, 1, mtr_dex::ED25519_SEED, 0, 0, 0, false, true);
        assert_eq!(signers.len(), 1);

        let signer = &signers[0];
        assert_eq!(signer.code(), mtr_dex::ED25519_SEED);
        assert_eq!(
            signer.qb64(),
            "AMGrAM0noxLpRteO9mxGT-yzYSrKFwJMuNI4KlmSk26e"
        );
        assert_eq!(signer.verfer().code(), mtr_dex::ED25519N);
        assert!(non_trans_dex::TUPLE.contains(&signer.verfer().code()));
        assert_eq!(
            signer.verfer().qb64(),
            "BFRtyHAjSuJaRX6TDPva35GN11VHAruaOXMc79ZYDKsT"
        );

        Ok(())
    }

    #[test]
    fn test_creatory_factory() -> Result<(), MatterError> {
        // Test Creatory with Randy algorithm
        let creatory = Creatory::new(Algos::Randy);
        let creator = creatory.make(None, None, None)?;

        // Verify it created a RandyCreator
        assert!(creator.salt().is_empty());
        assert!(creator.stem().is_empty());
        assert!(creator.tier().is_none());

        let signers = creator.create(None, None, None, None, None, None, None, None);
        assert_eq!(signers.len(), 1);
        assert_eq!(signers[0].code(), mtr_dex::ED25519_SEED);

        // Test Creatory with Salty algorithm and specific salt
        let raw = b"0123456789abcdef";
        let salt = Salter::new(Some(raw), None, None)?.qb64();

        let creatory = Creatory::new(Algos::Salty);
        let creator = creatory.make(Some(&salt), None, None)?;

        // Verify it created a SaltyCreator with correct salt
        assert_eq!(creator.salt(), salt);
        assert_eq!(creator.stem(), "");
        assert_eq!(creator.tier(), Some(&Tiers::LOW));

        // Test the CreatoryBuilder pattern
        let creator = CreatoryBuilder::new(Algos::Salty)
            .with_salt(&salt)
            .with_stem("test-stem")
            .with_tier(Tiers::HIGH)
            .build()?;

        assert_eq!(creator.salt(), salt);
        assert_eq!(creator.stem(), "test-stem");
        assert_eq!(creator.tier(), Some(&Tiers::HIGH));

        Ok(())
    }

    #[test]
    fn test_algos_enum() {
        // Test Algos enum conversion
        assert_eq!(Algos::Randy.to_string(), "randy");
        assert_eq!(Algos::Salty.to_string(), "salty");

        assert_eq!(Algos::from_str("randy").unwrap(), Algos::Randy);
        assert_eq!(Algos::from_str("RANDY").unwrap(), Algos::Randy);
        assert_eq!(Algos::from_str("salty").unwrap(), Algos::Salty);
        assert_eq!(Algos::from_str("SALTY").unwrap(), Algos::Salty);

        // Test error case
        let result = Algos::from_str("invalid");
        assert!(result.is_err());
    }

    #[test]
    fn test_error_handling() -> Result<(), MatterError> {
        // Test creation with invalid parameters
        let result = SaltyCreator::new(Some("invalid_salt"), None, None);
        assert!(result.is_err());

        Ok(())
    }

    #[test]
    fn test_deterministic_creation() -> Result<(), MatterError> {
        // Test that the same inputs produce the same outputs
        let raw = b"0123456789abcdef";
        let salt = Salter::new(Some(raw), None, None)?.qb64();

        let creator1 = SaltyCreator::new(Some(&salt), Some("test"), None)?;
        let creator2 = SaltyCreator::new(Some(&salt), Some("test"), None)?;

        let signers1 = creator1.create(None, None, None, None, None, None, None, None);
        let signers2 = creator2.create(None, None, None, None, None, None, None, None);

        assert_eq!(signers1[0].qb64(), signers2[0].qb64());
        assert_eq!(signers1[0].verfer().qb64(), signers2[0].verfer().qb64());

        // Different paths should produce different keys
        let creator3 = SaltyCreator::new(Some(&salt), Some("different"), None)?;
        let signers3 = creator3.create(None, None, None, None, None, None, None, None);

        assert_ne!(signers1[0].qb64(), signers3[0].qb64());
        assert_ne!(signers1[0].verfer().qb64(), signers3[0].verfer().qb64());

        Ok(())
    }

    #[test]
    fn test_create_with_codes() -> Result<(), MatterError> {
        // Test creating signers with specific codes
        let creator = RandyCreator::new();

        let codes = vec![mtr_dex::ED25519_SEED, mtr_dex::ED25519_SEED];
        let signers = creator.create(Some(codes), None, None, None, None, None, None, None);

        assert_eq!(signers.len(), 2);
        assert_eq!(signers[0].code(), mtr_dex::ED25519_SEED);
        assert_eq!(signers[1].code(), mtr_dex::ED25519_SEED);

        Ok(())
    }

    #[test]
    fn test_salty_creator_path_generation() -> Result<(), MatterError> {
        // Test that different paths generate different keys
        let raw = b"0123456789abcdef";
        let salt = Salter::new(Some(raw), None, None)?.qb64();

        let creator = SaltyCreator::new(Some(&salt), None, None)?;

        // Different paths through pidx, ridx, kidx
        let signers1 =
            creator.create_with_options(None, 1, mtr_dex::ED25519_SEED, 0, 0, 0, true, false);
        let signers2 =
            creator.create_with_options(None, 1, mtr_dex::ED25519_SEED, 1, 0, 0, true, false);
        let signers3 =
            creator.create_with_options(None, 1, mtr_dex::ED25519_SEED, 0, 1, 0, true, false);
        let signers4 =
            creator.create_with_options(None, 1, mtr_dex::ED25519_SEED, 0, 0, 1, true, false);

        // All should be different
        let key1 = signers1[0].qb64();
        let key2 = signers2[0].qb64();
        let key3 = signers3[0].qb64();
        let key4 = signers4[0].qb64();

        assert_ne!(key1, key2);
        assert_ne!(key1, key3);
        assert_ne!(key1, key4);
        assert_ne!(key2, key3);
        assert_ne!(key2, key4);
        assert_ne!(key3, key4);

        Ok(())
    }

    #[test]
    fn test_creator_defaults() -> Result<(), MatterError> {
        // Test default values
        let randy = RandyCreator::default();
        assert_eq!(randy.salt(), "");

        let creatory = Creatory::default();
        let creator = creatory.make(None, None, None)?;

        // Default should be SaltyCreator
        assert!(!creator.salt().is_empty());
        assert_eq!(creator.stem(), "");
        assert_eq!(creator.tier(), Some(&Tiers::LOW));

        Ok(())
    }
}
