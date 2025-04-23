use crate::cesr::signing::signer::Signer;
use crate::cesr::{mtr_dex, raw_size, BaseMatter, Parsable, Tiers};
use crate::errors::MatterError;
use crate::Matter;
use sodiumoxide::crypto::pwhash::argon2id13 as pwhash;
use sodiumoxide::crypto::pwhash::argon2id13::Salt;
use sodiumoxide::randombytes;
use std::any::Any;

/// Salter is Matter subclass to maintain random salt for secrets (private keys)
/// Its .raw is random salt, .code as cipher suite for salt
///
/// To initialize with deterministic salt pass in 16 bytes for raw:
///     salter = Salter::new(Some(b"0123456789abcdef"), None, None).unwrap();
///
/// To create a deterministic secret, seed, or private key from salt
/// call .signer:
///     signer = salter.signer(Some(mtr_dex::ED25519_SEED), Some(true), "", None, false).unwrap();
#[derive(Debug, Clone)]
pub struct Salter {
    base: BaseMatter,
    tier: Tiers,
}

impl Salter {
    /// Initialize salter's raw and code
    pub fn new(
        raw: Option<&[u8]>,
        code: Option<&str>,
        tier: Option<Tiers>,
    ) -> Result<Self, MatterError> {
        let code = code.unwrap_or(mtr_dex::SALT_128);

        let raw = match raw {
            Some(r) => r,
            None => {
                if code == mtr_dex::SALT_128 {
                    // Initialize sodium library if not already done
                    if sodiumoxide::init().is_err() {
                        return Err(MatterError::CryptoError(
                            "Sodium initialization failed".to_string(),
                        ));
                    }

                    // Generate random salt using sodiumoxide
                    let salt_bytes = randombytes::randombytes(pwhash::SALTBYTES);
                    &salt_bytes.clone()[..]
                } else {
                    return Err(MatterError::ValidationError(format!(
                        "Unsupported salter code = {}",
                        code
                    )));
                }
            }
        };

        if code != mtr_dex::SALT_128 {
            return Err(MatterError::ValidationError(format!(
                "Unsupported salter code = {}",
                code
            )));
        }

        // Use a default tier if none provided
        let tier = tier.unwrap_or(Tiers::LOW);

        let base = BaseMatter::new(Some(raw), Some(code), None, None)?;
        Ok(Self { base, tier })
    }

    /// Returns raw binary seed (secret) derived from path and .raw
    /// and stretched to size given by code using argon2id stretching algorithm.
    pub fn stretch(
        &self,
        size: usize,
        path: &str,
        tier: Option<&Tiers>,
        temp: bool,
    ) -> Result<Vec<u8>, MatterError> {
        let tier = tier.unwrap_or(&self.tier);

        let (opslimit, memlimit) = if temp {
            (pwhash::OpsLimit(1), pwhash::MemLimit(8192))
        } else {
            match tier {
                Tiers::LOW => (pwhash::OPSLIMIT_INTERACTIVE, pwhash::MEMLIMIT_INTERACTIVE),
                Tiers::MED => (pwhash::OPSLIMIT_MODERATE, pwhash::MEMLIMIT_MODERATE),
                Tiers::HIGH => (pwhash::OPSLIMIT_SENSITIVE, pwhash::MEMLIMIT_SENSITIVE),
            }
        };

        // Initialize sodium library if not already done
        if sodiumoxide::init().is_err() {
            return Err(MatterError::CryptoError(
                "Sodium initialization failed".to_string(),
            ));
        }

        // Convert path to bytes
        let path_bytes = path.as_bytes();

        // Create salt from raw
        let salt = match Salt::from_slice(self.raw()) {
            Some(s) => s,
            None => {
                return Err(MatterError::ValidationError(
                    "Invalid salt size".to_string(),
                ))
            }
        };

        // Use argon2id13 algorithm for stretching
        let mut kb = vec![0u8; size];
        let kb = kb.as_mut_slice();
        let seed = pwhash::derive_key(kb, path_bytes, &salt, opslimit, memlimit)
            .map_err(|_| MatterError::Conversion("Key derivation failed".to_string()))?;

        Ok(seed.to_vec())
    }

    /// Returns Signer instance whose .raw secret is derived from path and
    /// salter's .raw and stretched to size given by code. The signers public key
    /// for its .verfer is derived from code and transferable.
    pub fn signer(
        &self,
        code: Option<&str>,
        transferable: Option<bool>,
        path: &str,
        tier: Option<&Tiers>,
        temp: bool,
    ) -> Result<Signer, MatterError> {
        let code = code.unwrap_or(mtr_dex::ED25519_SEED);
        let transferable = transferable.unwrap_or(true);

        // Calculate raw size based on code
        let size = raw_size(code)?;

        let seed = self.stretch(size, path, tier, temp)?;

        Signer::new(Some(&seed), Some(code), Some(transferable))
    }

    /// Returns vector of count number of Signer instances with unique derivation
    /// path made from path prefix and suffix of start plus offset for each count
    /// value from 0 to count - 1.
    pub fn signers(
        &self,
        count: usize,
        start: usize,
        path: &str,
        code: Option<&str>,
        transferable: Option<bool>,
        tier: Option<&Tiers>,
        temp: bool,
    ) -> Result<Vec<Signer>, MatterError> {
        let mut signers = Vec::with_capacity(count);

        for i in 0..count {
            let path_with_suffix = format!("{}{:x}", path, i + start);
            let signer = self.signer(code, transferable, &path_with_suffix, tier, temp)?;
            signers.push(signer);
        }

        Ok(signers)
    }
}

impl Parsable for Salter {
    fn from_qb64b(data: &mut Vec<u8>, strip: Option<bool>) -> Result<Self, MatterError> {
        let base = BaseMatter::from_qb64b(data, strip)?;

        if base.code() != mtr_dex::SALT_128 {
            return Err(MatterError::ValidationError(format!(
                "Unsupported salter code = {}",
                base.code()
            )));
        }

        Ok(Self {
            base,
            tier: Tiers::LOW,
        })
    }

    fn from_qb2(data: &mut Vec<u8>, strip: Option<bool>) -> Result<Self, MatterError> {
        let base = BaseMatter::from_qb2(data, strip)?;

        if base.code() != mtr_dex::SALT_128 {
            return Err(MatterError::ValidationError(format!(
                "Unsupported salter code = {}",
                base.code()
            )));
        }

        Ok(Self {
            base,
            tier: Tiers::LOW,
        })
    }
}

impl Matter for Salter {
    fn code(&self) -> &str {
        self.base.code()
    }

    fn raw(&self) -> &[u8] {
        self.base.raw()
    }

    fn qb64(&self) -> String {
        self.base.qb64()
    }

    fn qb64b(&self) -> Vec<u8> {
        self.base.qb64b()
    }

    fn qb2(&self) -> Vec<u8> {
        self.base.qb2()
    }

    fn soft(&self) -> &str {
        self.base.soft()
    }

    fn full_size(&self) -> usize {
        self.base.full_size()
    }

    fn size(&self) -> usize {
        self.base.size()
    }

    fn is_transferable(&self) -> bool {
        self.base.is_transferable()
    }

    fn is_digestive(&self) -> bool {
        self.base.is_digestive()
    }

    fn is_prefixive(&self) -> bool {
        self.base.is_prefixive()
    }

    fn is_special(&self) -> bool {
        self.base.is_special()
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_salter_creation() {
        // Create salter with random salt
        let salter = Salter::new(None, None, None).unwrap();
        assert_eq!(salter.code(), mtr_dex::SALT_128);
        assert_eq!(salter.raw().len(), 16); // Salt_128 should be 16 bytes

        // Create salter with specific salt
        let raw = b"0123456789abcdef";
        let salter = Salter::new(Some(raw), None, None).unwrap();
        assert_eq!(salter.code(), mtr_dex::SALT_128);
        assert_eq!(salter.raw(), raw);
    }

    #[test]
    fn test_stretching() {
        let raw = b"0123456789abcdef";
        let salter = Salter::new(Some(raw), None, None).unwrap();

        // Test with temp=true for faster tests
        let stretched = salter.stretch(32, "test-path", None, true).unwrap();
        assert_eq!(stretched.len(), 32);

        // Same inputs should produce same output
        let stretched2 = salter.stretch(32, "test-path", None, true).unwrap();
        assert_eq!(stretched, stretched2);

        // Different path should produce different output
        let stretched3 = salter.stretch(32, "different-path", None, true).unwrap();
        assert_ne!(stretched, stretched3);
    }

    #[test]
    fn test_signer_creation() {
        let raw = b"0123456789abcdef";
        let salter = Salter::new(Some(raw), None, None).unwrap();

        // Create a signer with temp=true for faster tests
        let signer = salter.signer(None, None, "test-path", None, true).unwrap();

        // Should have created an Ed25519 signer by default
        assert_eq!(signer.code(), mtr_dex::ED25519_SEED);
        assert!(signer.is_transferable());

        // Creating another signer with same parameters should give same key
        let signer2 = salter.signer(None, None, "test-path", None, true).unwrap();
        assert_eq!(signer.raw(), signer2.raw());
    }

    #[test]
    fn test_signers_creation() {
        let raw = b"0123456789abcdef";
        let salter = Salter::new(Some(raw), None, None).unwrap();

        // Create multiple signers
        let signers = salter
            .signers(3, 0, "test-path", None, None, None, true)
            .unwrap();

        // Should have 3 signers
        assert_eq!(signers.len(), 3);

        // Each signer should be different
        assert_ne!(signers[0].raw(), signers[1].raw());
        assert_ne!(signers[1].raw(), signers[2].raw());
        assert_ne!(signers[0].raw(), signers[2].raw());
    }

    #[test]
    fn test_salter_default() {
        // Test default constructor
        let salter = Salter::new(None, None, None).unwrap();
        assert_eq!(salter.code(), mtr_dex::SALT_128);
        assert_eq!(salter.raw().len(), 16); // Same as Matter::raw_size(salter.code())
    }

    #[test]
    fn test_salter_with_raw() {
        // Test constructor with raw bytes
        let raw = b"0123456789abcdef";
        let salter = Salter::new(Some(raw), None, None).unwrap();
        assert_eq!(salter.raw(), raw);
        assert_eq!(salter.qb64(), "0AAwMTIzNDU2Nzg5YWJjZGVm");
    }

    #[test]
    fn test_salter_from_qb64() {
        // Test constructor from qb64
        let qb64 = "0AAwMTIzNDU2Nzg5YWJjZGVm";
        let salter = Salter::from_qb64b(&mut qb64.as_bytes().to_vec(), None).unwrap();
        assert_eq!(salter.raw(), b"0123456789abcdef");
        assert_eq!(salter.qb64(), qb64);
    }

    #[test]
    fn test_salter_empty_qb64() {
        // Test that empty qb64 fails
        let result = Salter::from_qb64b(&mut "".as_bytes().to_vec(), None);
        assert!(result.is_err());
    }

    #[test]
    fn test_signer_with_temp() {
        // Test signer creation with temp=true
        let raw = b"0123456789abcdef";
        let salter = Salter::new(Some(raw), None, None).unwrap();
        assert_eq!(salter.code(), mtr_dex::SALT_128);
        assert_eq!(salter.qb64(), "0AAwMTIzNDU2Nzg5YWJjZGVm");

        let signer = salter.signer(None, None, "01", None, true).unwrap();

        assert_eq!(signer.code(), mtr_dex::ED25519_SEED);
        assert_eq!(signer.raw().len(), 32); // Expected size for Ed25519_Seed
        assert_eq!(signer.verfer().code(), mtr_dex::ED25519);
        assert_eq!(signer.verfer().raw().len(), 32); // Expected size for Ed25519
        assert_eq!(
            signer.qb64(),
            "AMPsqBZxWdtYpBhrWnKYitwFa77s902Q-nX3sPTzqs0R"
        );
        assert_eq!(
            signer.verfer().qb64(),
            "DFYFwZJOMNy3FknECL8tUaQZRBUyQ9xCv6F8ckG-UCrC"
        );
    }

    #[test]
    fn test_signer_without_temp() {
        // Test signer creation with temp=false (default)
        let raw = b"0123456789abcdef";
        let salter = Salter::new(Some(raw), None, None).unwrap();

        let signer = salter.signer(None, None, "01", None, false).unwrap();

        assert_eq!(signer.code(), mtr_dex::ED25519_SEED);
        assert_eq!(signer.raw().len(), 32); // Expected size for Ed25519_Seed
        assert_eq!(signer.verfer().code(), mtr_dex::ED25519);
        assert_eq!(signer.verfer().raw().len(), 32); // Expected size for Ed25519
        assert_eq!(
            signer.qb64(),
            "AEkqQiNTexWB9fTLpgJp_lXW63tFlT-Y0_mgQww4o-dC"
        );
        assert_eq!(
            signer.verfer().qb64(),
            "DPJGyH9H1M_SUSf18RzX8OqdyhxEyZJpKm5Em0PnpsWd"
        );
    }

    #[test]
    fn test_stretch() {
        // Test stretching key material with different parameters
        let raw = b"0123456789abcdef";
        let salter = Salter::new(Some(raw), None, None).unwrap();

        // Test with temp=true
        let stretched_temp = salter.stretch(32, "", Some(&Tiers::LOW), true).unwrap();
        assert_eq!(
            stretched_temp,
            [
                212, 64, 235, 166, 120, 134, 223, 147, 214, 67, 220, 184, 166, 155, 2, 175, 104,
                193, 109, 40, 76, 214, 246, 134, 89, 85, 62, 36, 91, 249, 239, 192
            ]
        );

        // Test with Tiers::Low
        let stretched_low = salter.stretch(32, "", Some(&Tiers::LOW), false).unwrap();
        assert_eq!(
            stretched_low,
            [
                248, 101, 128, 186, 88, 8, 185, 186, 198, 30, 132, 13, 29, 172, 167, 92, 130, 87,
                99, 64, 96, 19, 253, 2, 52, 116, 140, 116, 211, 1, 25, 233
            ]
        );

        // Test with Tiers::Med
        let stretched_med = salter.stretch(32, "", Some(&Tiers::MED), false).unwrap();
        assert_eq!(
            stretched_med,
            [
                44, 243, 140, 187, 233, 41, 10, 83, 81, 236, 173, 140, 57, 63, 175, 184, 176, 179,
                205, 66, 218, 216, 182, 247, 13, 246, 68, 125, 90, 185, 89, 22
            ]
        );

        // Test with Tiers::High
        let stretched_high = salter.stretch(32, "", Some(&Tiers::HIGH), false).unwrap();
        assert_eq!(
            stretched_high,
            [
                40, 205, 196, 184, 53, 205, 232, 58, 252, 0, 139, 253, 166, 9, 106, 46, 121, 152,
                11, 4, 28, 227, 104, 66, 99, 33, 73, 228, 57, 75, 22, 45
            ]
        );
    }

    #[test]
    fn test_multiple_signers() {
        // Test creating multiple signers
        let raw = b"0123456789abcdef";
        let salter = Salter::new(Some(raw), None, None).unwrap();

        // Create 3 signers starting at index 0
        let signers = salter
            .signers(3, 0, "test-path", None, None, None, false)
            .unwrap();

        assert_eq!(signers.len(), 3);
        for signer in &signers {
            assert_eq!(signer.code(), mtr_dex::ED25519_SEED);
            assert_eq!(signer.verfer().code(), mtr_dex::ED25519);
        }

        // Verify signers are different from each other
        assert_ne!(signers[0].qb64(), signers[1].qb64());
        assert_ne!(signers[0].qb64(), signers[2].qb64());
        assert_ne!(signers[1].qb64(), signers[2].qb64());
    }

    #[test]
    fn test_salter_parsable() {
        // Test Parsable implementation for Salter
        let raw = b"0123456789abcdef";
        let salter = Salter::new(Some(raw), None, None).unwrap();

        // Convert to qb64b and parse back
        let mut qb64b = salter.qb64b();
        let parsed_salter = Salter::from_qb64b(&mut qb64b, Some(true)).unwrap();
        assert_eq!(parsed_salter.raw(), raw);

        // Convert to qb2 and parse back
        // TODO: Come back to this test for from_qb2
        // let mut qb2 = salter.qb2();
        // let parsed_salter = Salter::from_qb2(&mut qb2, Some(true)).unwrap();
        assert_eq!(parsed_salter.raw(), raw);
    }
}
