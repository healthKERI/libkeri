use crate::cesr::cigar::Cigar;
use crate::cesr::indexing::idr_dex;
use crate::cesr::indexing::siger::Siger;
use crate::cesr::signing::Sigmat;
use crate::cesr::verfer::Verfer;
use crate::cesr::{mtr_dex, BaseMatter, Parsable};
use crate::errors::MatterError;
use crate::Matter;
use p256::ecdsa::SigningKey;
use rand_core::{OsRng, RngCore};
use secp256k1::{Message, Secp256k1, SecretKey};
use sha3::{Digest, Sha3_256};
use sodiumoxide::crypto::sign::ed25519;
use sodiumoxide::randombytes;
use std::any::Any;

/// Signer is a Matter subclass with method to create signature of serialization
/// using:
///     .raw as signing (private) key seed,
///     .code as cipher suite for signing
///     .verfer whose property .raw is public key for signing.
///
/// If not provided, .verfer is generated from private key seed using .code
/// as cipher suite for creating key-pair.
#[derive(Debug, Clone)]
pub struct Signer {
    base: BaseMatter,
    pub verfer: Verfer,
}

impl Signer {
    /// Create a new Signer with the given parameters
    pub fn new(
        raw: Option<&[u8]>,
        code: Option<&str>,
        transferable: Option<bool>,
    ) -> Result<Self, MatterError> {
        // Default code is Ed25519_Seed
        let code = code.unwrap_or(mtr_dex::ED25519_SEED);
        let transferable = transferable.unwrap_or(true);

        // Handle the case when raw is None (generate random key)
        let raw_bytes = match raw {
            Some(bytes) => bytes.to_vec(),
            None => {
                match code {
                    mtr_dex::ED25519_SEED => {
                        sodiumoxide::init().map_err(|_| {
                            MatterError::CryptoError("Sodium initialization failed".into())
                        })?;
                        let seed = randombytes::randombytes(ed25519::SEEDBYTES);
                        seed[..].to_vec()
                    }
                    mtr_dex::ECDSA_256R1_SEED => {
                        let mut seed = vec![0u8; 32]; // P256 seeds are 32 bytes
                        OsRng.fill_bytes(&mut seed);
                        seed
                    }
                    mtr_dex::ECDSA_256K1_SEED => {
                        let mut seed = vec![0u8; 32]; // Secp256k1 seeds are 32 bytes
                        OsRng.fill_bytes(&mut seed);
                        seed
                    }
                    _ => {
                        return Err(MatterError::UnexpectedCode(format!(
                            "Unsupported signer code: {}",
                            code
                        )))
                    }
                }
            }
        };

        // Create base matter
        let base = BaseMatter::new(Some(&raw_bytes), Some(code), None, None)?;

        // Generate verfer based on the signing key
        let verfer = match code {
            mtr_dex::ED25519_SEED => {
                let raw_bytes: [u8; 32] = raw_bytes
                    .try_into()
                    .map_err(|_| MatterError::CryptoError("Invalid Ed25519 seed".into()))?;

                sodiumoxide::init()
                    .map_err(|_| MatterError::CryptoError("Sodium initialization failed".into()))?;
                let seed = ed25519::Seed::from_slice(&raw_bytes)
                    .ok_or_else(|| MatterError::CryptoError("Invalid Ed25519 seed".to_string()))?;
                let (pk, _) = ed25519::keypair_from_seed(&seed);
                let verfer_code = if transferable {
                    mtr_dex::ED25519
                } else {
                    mtr_dex::ED25519N
                };
                Verfer::new(Some(&pk[..]), Some(verfer_code))?
            }
            mtr_dex::ECDSA_256R1_SEED => {
                let signing_key = SigningKey::from_slice(&raw_bytes)
                    .map_err(|_| MatterError::CryptoError("Invalid P256 seed".into()))?;
                let verkey = signing_key
                    .verifying_key()
                    .to_encoded_point(true)
                    .as_bytes()
                    .to_vec();
                let verfer_code = if transferable {
                    mtr_dex::ECDSA_256R1
                } else {
                    mtr_dex::ECDSA_256R1N
                };
                Verfer::new(Some(&verkey), Some(verfer_code))?
            }
            mtr_dex::ECDSA_256K1_SEED => {
                let raw_bytes: [u8; 32] = raw_bytes
                    .try_into()
                    .map_err(|_| MatterError::CryptoError("Invalid Secp256k1 seed".into()))?;

                let secp = Secp256k1::new();
                let secret_key = SecretKey::from_byte_array(&raw_bytes)
                    .map_err(|_| MatterError::CryptoError("Invalid Secp256k1 seed".into()))?;
                let public_key = secp256k1::PublicKey::from_secret_key(&secp, &secret_key);
                let verkey = public_key.serialize();
                let verfer_code = if transferable {
                    mtr_dex::ECDSA_256K1
                } else {
                    mtr_dex::ECDSA_256K1N
                };
                Verfer::new(Some(&verkey), Some(verfer_code))?
            }
            _ => {
                return Err(MatterError::UnexpectedCode(format!(
                    "Unsupported signer code: {}",
                    code
                )))
            }
        };

        Ok(Self { base, verfer })
    }

    /// Create a Signer from raw bytes using default code
    pub fn from_raw(raw: Option<&[u8]>) -> Result<Self, MatterError> {
        Self::new(raw, None, None)
    }

    /// Get the verfer associated with this signer
    pub fn verfer(&self) -> &Verfer {
        &self.verfer
    }
    pub fn set_verfer(&mut self, verfer: Verfer) {
        self.verfer = verfer;
    }

    /// Sign the serialization and return a signature (Cigar or Siger)
    pub fn sign(
        &self,
        ser: &[u8],
        index: Option<u32>,
        only: Option<bool>,
        ondex: Option<u32>,
    ) -> Result<Sigmat, MatterError> {
        let only = only.unwrap_or(false);

        match self.base.code() {
            mtr_dex::ED25519_SEED => self.sign_ed25519(ser, index, only, ondex),
            mtr_dex::ECDSA_256R1_SEED => self.sign_secp256r1(ser, index, only, ondex),
            mtr_dex::ECDSA_256K1_SEED => self.sign_secp256k1(ser, index, only, ondex),
            _ => Err(MatterError::UnexpectedCode(format!(
                "Unsupported signer code: {}",
                self.base.code()
            ))),
        }
    }

    /// Sign using Ed25519
    fn sign_ed25519(
        &self,
        ser: &[u8],
        index: Option<u32>,
        only: bool,
        ondex: Option<u32>,
    ) -> Result<Sigmat, MatterError> {
        sodiumoxide::init()
            .map_err(|_| MatterError::CryptoError("Sodium initialization failed".into()))?;

        let seed = ed25519::Seed::from_slice(self.base.raw())
            .ok_or_else(|| MatterError::CryptoError("Invalid Ed25519 seed".into()))?;
        let (_, sk) = ed25519::keypair_from_seed(&seed);

        let signed = ed25519::sign_detached(ser, &sk);
        let sig = signed.as_ref();
        let mut ondex = ondex;

        match index {
            None => {
                // Non-indexed signature (Cigar)
                let cigar = Cigar::new(
                    Some(sig),
                    Some(mtr_dex::ED25519_SIG),
                    None,
                    None,
                    Some(self.verfer.clone()),
                )?;
                Ok(Sigmat::NonIndexed(cigar))
            }
            Some(idx) => {
                // Indexed signature (Siger)
                let code = if only {
                    // Only main index
                    ondex = None;
                    if idx <= 63 {
                        idr_dex::ED25519_CRT_SIG // Small current only
                    } else {
                        idr_dex::ED25519_BIG_CRT_SIG // Big current only
                    }
                } else {
                    // Both indices
                    let ondex_val = ondex.unwrap_or(idx); // Default to same as index
                    if ondex_val == idx && idx <= 63 {
                        idr_dex::ED25519_SIG // Small both same
                    } else {
                        idr_dex::ED25519_BIG_SIG // Big both
                    }
                };

                let siger = Siger::new(
                    Some(sig),
                    Some(code),
                    Some(idx),
                    ondex,
                    Some(self.verfer.clone()),
                )?;

                Ok(Sigmat::Indexed(siger))
            }
        }
    }

    /// Sign using SECP256R1 (P-256)
    fn sign_secp256r1(
        &self,
        ser: &[u8],
        index: Option<u32>,
        only: bool,
        ondex: Option<u32>,
    ) -> Result<Sigmat, MatterError> {
        let signing_key = SigningKey::from_slice(self.base.raw())
            .map_err(|_| MatterError::CryptoError("Invalid P256 seed".into()))?;

        // Sign the message
        let (signature, _) = match signing_key.sign_recoverable(ser) {
            Ok(sig) => sig,
            Err(_) => {
                return Err(MatterError::CryptoError(
                    "Invalid message for signing".into(),
                ));
            }
        };

        // Extract r and s components
        let r_bytes = signature.r().to_bytes();
        let s_bytes = signature.s().to_bytes();

        // Combine r and s into a single signature
        let mut sig = Vec::with_capacity(64);
        sig.extend_from_slice(&r_bytes);
        sig.extend_from_slice(&s_bytes);

        match index {
            None => {
                // Non-indexed signature (Cigar)
                let cigar = Cigar::new(
                    Some(&sig),
                    Some(mtr_dex::ECDSA_256R1_SIG),
                    None,
                    None,
                    Some(self.verfer.clone()),
                )?;
                Ok(Sigmat::NonIndexed(cigar))
            }
            Some(idx) => {
                // Indexed signature (Siger)
                let code = if only {
                    // Only main index
                    if idx <= 63 {
                        idr_dex::ECDSA_256R1_CRT_SIG // Small current only
                    } else {
                        idr_dex::ECDSA_256R1_BIG_CRT_SIG // Big current only
                    }
                } else {
                    // Both indices
                    let ondex_val = ondex.unwrap_or(idx); // Default to same as index
                    if ondex_val == idx && idx <= 63 {
                        idr_dex::ECDSA_256R1_SIG // Small both same
                    } else {
                        idr_dex::ECDSA_256R1_BIG_SIG // Big both
                    }
                };

                let siger = Siger::new(
                    Some(&sig),
                    Some(code),
                    Some(idx),
                    ondex,
                    Some(self.verfer.clone()),
                )?;

                Ok(Sigmat::Indexed(siger))
            }
        }
    }

    /// Sign using SECP256K1
    fn sign_secp256k1(
        &self,
        ser: &[u8],
        index: Option<u32>,
        only: bool,
        ondex: Option<u32>,
    ) -> Result<Sigmat, MatterError> {
        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_slice(self.base.raw())
            .map_err(|_| MatterError::CryptoError("Invalid Secp256k1 seed".into()))?;

        // Create a message object from the serialization
        let mut hasher = Sha3_256::new();
        hasher.update(ser);
        let result = hasher.finalize();
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&result);

        let message = Message::from_digest(digest);

        // Sign the message
        let signature = secp.sign_ecdsa(&message, &secret_key);

        // Extract r and s components
        let sig_bytes = signature.serialize_compact();

        match index {
            None => {
                // Non-indexed signature (Cigar)
                let cigar = Cigar::new(
                    Some(&sig_bytes),
                    Some(mtr_dex::ECDSA_256K1_SIG),
                    None,
                    None,
                    Some(self.verfer.clone()),
                )?;
                Ok(Sigmat::NonIndexed(cigar))
            }
            Some(idx) => {
                // Indexed signature (Siger)
                let code = if only {
                    // Only main index
                    if idx <= 63 {
                        idr_dex::ECDSA_256K1_CRT_SIG // Small current only
                    } else {
                        idr_dex::ECDSA_256K1_BIG_CRT_SIG // Big current only
                    }
                } else {
                    // Both indices
                    let ondex_val = ondex.unwrap_or(idx); // Default to same as index
                    if ondex_val == idx && idx <= 63 {
                        idr_dex::ECDSA_256K1_SIG // Small both same
                    } else {
                        idr_dex::ECDSA_256K1_BIG_SIG // Big both
                    }
                };

                let siger = Siger::new(
                    Some(&sig_bytes),
                    Some(code),
                    Some(idx),
                    ondex,
                    Some(self.verfer.clone()),
                )?;

                Ok(Sigmat::Indexed(siger))
            }
        }
    }

    pub fn from_qb64b_and_transferable(
        data: &mut Vec<u8>,
        strip: Option<bool>,
        transferable: bool,
    ) -> Result<Self, MatterError> {
        let mut signer = Signer::from_qb64b(data, strip)?;
        // Generate verfer based on the signing key
        let verfer = match signer.code() {
            mtr_dex::ED25519_SEED => {
                let raw_bytes: [u8; 32] = signer
                    .raw()
                    .try_into()
                    .map_err(|_| MatterError::CryptoError("Invalid Ed25519 seed".into()))?;

                sodiumoxide::init()
                    .map_err(|_| MatterError::CryptoError("Sodium initialization failed".into()))?;
                let seed = ed25519::Seed::from_slice(&raw_bytes)
                    .ok_or_else(|| MatterError::CryptoError("Invalid Ed25519 seed".to_string()))?;
                let (pk, _) = ed25519::keypair_from_seed(&seed);
                let verfer_code = if transferable {
                    mtr_dex::ED25519
                } else {
                    mtr_dex::ED25519N
                };
                Verfer::new(Some(&pk[..]), Some(verfer_code))?
            }
            mtr_dex::ECDSA_256R1_SEED => {
                let signing_key = SigningKey::from_slice(&signer.raw())
                    .map_err(|_| MatterError::CryptoError("Invalid P256 seed".into()))?;
                let verkey = signing_key
                    .verifying_key()
                    .to_encoded_point(true)
                    .as_bytes()
                    .to_vec();
                let verfer_code = if transferable {
                    mtr_dex::ECDSA_256R1
                } else {
                    mtr_dex::ECDSA_256R1N
                };
                Verfer::new(Some(&verkey), Some(verfer_code))?
            }
            mtr_dex::ECDSA_256K1_SEED => {
                let raw_bytes: [u8; 32] = signer
                    .raw()
                    .try_into()
                    .map_err(|_| MatterError::CryptoError("Invalid Secp256k1 seed".into()))?;

                let secp = Secp256k1::new();
                let secret_key = SecretKey::from_byte_array(&raw_bytes)
                    .map_err(|_| MatterError::CryptoError("Invalid Secp256k1 seed".into()))?;
                let public_key = secp256k1::PublicKey::from_secret_key(&secp, &secret_key);
                let verkey = public_key.serialize();
                let verfer_code = if transferable {
                    mtr_dex::ECDSA_256K1
                } else {
                    mtr_dex::ECDSA_256K1N
                };
                Verfer::new(Some(&verkey), Some(verfer_code))?
            }
            _ => {
                return Err(MatterError::UnexpectedCode(format!(
                    "Unsupported signer code: {}",
                    signer.code()
                )))
            }
        };

        signer.set_verfer(verfer);
        Ok(signer)
    }
}

impl Parsable for Signer {
    fn from_qb64b(data: &mut Vec<u8>, strip: Option<bool>) -> Result<Self, MatterError> {
        let base = BaseMatter::from_qb64b(data, strip)?;

        // Create a Signer from the base matter
        let raw = base.raw();
        let code = base.code();

        Self::new(Some(raw), Some(code), None)
    }

    fn from_qb2(data: &mut Vec<u8>, strip: Option<bool>) -> Result<Self, MatterError> {
        let base = BaseMatter::from_qb2(data, strip)?;

        // Create a Signer from the base matter
        let raw = base.raw();
        let code = base.code();

        Self::new(Some(raw), Some(code), None)
    }
}

impl Matter for Signer {
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
    use crate::cesr::indexing::siger::Siger;
    use crate::cesr::indexing::{raw_size, Indexer};
    use crate::cesr::raw_size as mtr_raw_size;
    use sodiumoxide::randombytes;

    #[test]
    fn test_signer_creation() {
        // Test creation with random seed
        let signer = Signer::new(None, None, None).unwrap();
        assert_eq!(signer.code(), mtr_dex::ED25519_SEED);

        // Test that verfer is created correctly
        let verfer = signer.verfer();
        assert_eq!(verfer.code(), mtr_dex::ED25519);

        // Test non-transferable
        let signer = Signer::new(None, None, Some(false)).unwrap();
        let verfer = signer.verfer();
        assert_eq!(verfer.code(), mtr_dex::ED25519N);
    }

    #[test]
    fn test_signing() {
        // Create a signer
        let signer = Signer::new(None, None, None).unwrap();

        // Test data to sign
        let ser = b"test data";

        // Sign without index (Cigar)
        let Sigmat::NonIndexed(signature) = signer.sign(ser, None, None, None).unwrap() else {
            panic!("Invalid type")
        };
        assert_eq!(signature.code(), mtr_dex::ED25519_SIG);

        // Sign with index (Siger)
        let Sigmat::Indexed(signature) = signer.sign(ser, Some(0), None, None).unwrap() else {
            panic!("Invalid type")
        };
        assert_eq!(signature.code(), idr_dex::ED25519_SIG);

        // Sign with large index
        let Sigmat::Indexed(signature) = signer.sign(ser, Some(100), None, None).unwrap() else {
            panic!("Invalid type")
        };
        assert_eq!(signature.code(), idr_dex::ED25519_BIG_SIG);

        // Sign with only=true
        let Sigmat::Indexed(signature) = signer.sign(ser, Some(0), Some(true), None).unwrap()
        else {
            panic!("Invalid type")
        };
        assert_eq!(signature.code(), idr_dex::ED25519_CRT_SIG);
    }

    #[test]
    fn test_signer() -> Result<(), MatterError> {
        // Test default Signer instance (Ed25519)
        let signer = Signer::new(None, None, None)?;
        assert_eq!(signer.code(), mtr_dex::ED25519_SEED);
        assert_eq!(signer.raw().len(), mtr_raw_size(mtr_dex::ED25519_SEED)?);
        assert_eq!(signer.verfer().code(), mtr_dex::ED25519);
        assert_eq!(signer.verfer().raw().len(), mtr_raw_size(mtr_dex::ED25519)?);

        // Create something to sign and verify
        let ser = b"abcdefghijklmnopqrstuvwxyz0123456789";

        let Sigmat::NonIndexed(cigar) = signer.sign(ser, None, None, None)? else {
            panic!("Invalid type")
        };
        assert_eq!(cigar.code(), mtr_dex::ED25519_SIG);
        assert_eq!(cigar.raw().len(), mtr_raw_size(mtr_dex::ED25519_SIG)?);
        let result = signer.verfer().verify(cigar.raw(), ser)?;
        assert!(result);

        // Test with index
        let index = 0;
        let Sigmat::Indexed(siger) = signer.sign(ser, Some(index), None, None)? else {
            panic!("Invalid type")
        };
        let siger = siger.as_any().downcast_ref::<Siger>().unwrap();
        assert_eq!(siger.code(), idr_dex::ED25519_SIG);
        assert_eq!(siger.raw().len(), mtr_raw_size(mtr_dex::ED25519_SIG)?);
        assert_eq!(siger.index(), index);
        assert_eq!(siger.ondex(), Some(index));
        let result = signer.verfer().verify(siger.raw(), ser)?;
        assert!(result);

        // Test verification with invalid data
        // let invalid_ser: &[&[u8]] = [ser, b"ABCDEFG"].concat();
        // let result = signer.verfer().verify(siger.raw(), &invalid_ser)?;
        // assert!(!result);

        // Raw values should be the same
        assert_eq!(cigar.raw(), siger.raw());

        // Test with invalid code (not a SEED type)
        let result = Signer::new(None, Some(mtr_dex::ED25519N), None);
        assert!(result.is_err());

        // Test non-transferable
        let signer = Signer::new(None, None, Some(false))?;
        assert_eq!(signer.code(), mtr_dex::ED25519_SEED);
        assert_eq!(signer.raw().len(), mtr_raw_size(mtr_dex::ED25519_SEED)?);
        assert_eq!(signer.verfer().code(), mtr_dex::ED25519N);
        assert_eq!(
            signer.verfer().raw().len(),
            mtr_raw_size(mtr_dex::ED25519N)?
        );

        let Sigmat::NonIndexed(cigar) = signer.sign(ser, None, None, None)? else {
            panic!("Invalid type")
        };
        assert_eq!(cigar.code(), mtr_dex::ED25519_SIG);
        assert_eq!(cigar.raw().len(), mtr_raw_size(mtr_dex::ED25519_SIG)?);
        let result = signer.verfer().verify(cigar.raw(), ser)?;
        assert!(result);

        // Test with index for non-transferable
        let Sigmat::Indexed(siger) = signer.sign(ser, Some(0), None, None)? else {
            panic!("Invalid type")
        };
        assert_eq!(siger.code(), idr_dex::ED25519_SIG);
        assert_eq!(siger.raw().len(), mtr_raw_size(mtr_dex::ED25519_SIG)?);
        assert_eq!(siger.index(), index);
        assert_eq!(siger.ondex(), Some(index));
        let result = signer.verfer().verify(siger.raw(), ser)?;
        assert!(result);

        // Test verification with invalid data
        let invalid_ser: [&[u8]; 2] = [ser, b"ABCDEFG"];
        let result = signer.verfer().verify(siger.raw(), &invalid_ser.concat())?;
        assert!(!result);

        // Test non-default seed
        sodiumoxide::init().unwrap();
        let seed = randombytes::randombytes(32); // SEEDBYTES for Ed25519
        let signer = Signer::new(Some(&seed), Some(mtr_dex::ED25519_SEED), None)?;
        assert_eq!(signer.code(), mtr_dex::ED25519_SEED);
        assert_eq!(signer.raw().len(), mtr_raw_size(mtr_dex::ED25519_SEED)?);
        assert_eq!(signer.raw(), seed);
        assert_eq!(signer.verfer().code(), mtr_dex::ED25519);
        assert_eq!(signer.verfer().raw().len(), mtr_raw_size(mtr_dex::ED25519)?);

        let Sigmat::NonIndexed(cigar) = signer.sign(ser, None, None, None)? else {
            panic!("Invalid type")
        };
        assert_eq!(cigar.code(), mtr_dex::ED25519_SIG);
        assert_eq!(cigar.raw().len(), mtr_raw_size(mtr_dex::ED25519_SIG)?);
        let result = signer.verfer().verify(cigar.raw(), ser)?;
        assert!(result);

        // Test with different index
        let index = 1;
        let Sigmat::Indexed(siger) = signer.sign(ser, Some(index), None, None)? else {
            panic!("Invalid type")
        };
        assert_eq!(siger.code(), idr_dex::ED25519_SIG);
        assert_eq!(siger.raw().len(), mtr_raw_size(mtr_dex::ED25519_SIG)?);
        assert_eq!(siger.index(), index);
        assert_eq!(siger.ondex(), Some(index));
        let result = signer.verfer().verify(siger.raw(), ser)?;
        assert!(result);

        // Raw should match
        assert_eq!(cigar.raw(), siger.raw());

        // Test with different index and ondex - should use Big format
        let index = 1;
        let ondex = 3;
        let Sigmat::Indexed(siger) = signer.sign(ser, Some(index), None, Some(ondex))? else {
            panic!("Invalid type")
        };
        assert_eq!(siger.code(), idr_dex::ED25519_BIG_SIG);
        assert_eq!(siger.raw().len(), raw_size(idr_dex::ED25519_BIG_SIG)?);
        assert_eq!(siger.index(), index);
        assert_eq!(siger.ondex(), Some(ondex));
        let result = signer.verfer().verify(siger.raw(), ser)?;
        assert!(result);

        // Test Big index (same index, ondex)
        let index = 67;
        let Sigmat::Indexed(siger) = signer.sign(ser, Some(index), None, None)? else {
            panic!("Invalid type")
        };
        assert_eq!(siger.code(), idr_dex::ED25519_BIG_SIG);
        assert_eq!(siger.raw().len(), raw_size(idr_dex::ED25519_BIG_SIG)?);
        assert_eq!(siger.index(), index);
        assert_eq!(siger.ondex(), Some(index));
        let result = signer.verfer().verify(siger.raw(), ser)?;
        assert!(result);

        // Test Big index with different ondex
        let ondex = 67;
        let Sigmat::Indexed(siger) = signer.sign(ser, Some(index), None, Some(ondex))? else {
            panic!("Invalid type")
        };
        assert_eq!(siger.code(), idr_dex::ED25519_BIG_SIG);
        assert_eq!(siger.raw().len(), raw_size(idr_dex::ED25519_BIG_SIG)?);
        assert_eq!(siger.index(), index);
        assert_eq!(siger.ondex(), Some(ondex));
        let result = signer.verfer().verify(siger.raw(), ser)?;
        assert!(result);

        // Test current only
        let index = 4;
        let Sigmat::Indexed(siger) = signer.sign(ser, Some(index), Some(true), None)? else {
            panic!("Invalid type")
        };
        assert_eq!(siger.code(), idr_dex::ED25519_CRT_SIG);
        assert_eq!(siger.raw().len(), raw_size(idr_dex::ED25519_CRT_SIG)?);
        assert_eq!(siger.index(), index);
        assert_eq!(siger.ondex(), None);
        let result = signer.verfer().verify(siger.raw(), ser)?;
        assert!(result);

        // Test current only ignores ondex
        let Sigmat::Indexed(siger) = signer.sign(ser, Some(index), Some(true), Some(index + 2))?
        else {
            panic!("Invalid type")
        };
        assert_eq!(siger.code(), idr_dex::ED25519_CRT_SIG);
        assert_eq!(siger.raw().len(), raw_size(idr_dex::ED25519_CRT_SIG)?);
        assert_eq!(siger.index(), index);
        assert_eq!(siger.ondex(), None);
        let result = signer.verfer().verify(siger.raw(), ser)?;
        assert!(result);

        // Test big current only
        let index = 65;
        let Sigmat::Indexed(siger) = signer.sign(ser, Some(index), Some(true), None)? else {
            panic!("Invalid type")
        };
        assert_eq!(siger.code(), idr_dex::ED25519_BIG_CRT_SIG);
        assert_eq!(siger.raw().len(), raw_size(idr_dex::ED25519_BIG_CRT_SIG)?);
        assert_eq!(siger.index(), index);
        assert_eq!(siger.ondex(), None);
        let result = signer.verfer().verify(siger.raw(), ser)?;
        assert!(result);

        // Test big current only ignores ondex
        let Sigmat::Indexed(siger) = signer.sign(ser, Some(index), Some(true), Some(index + 2))?
        else {
            panic!("Invalid type")
        };
        assert_eq!(siger.code(), idr_dex::ED25519_BIG_CRT_SIG);
        assert_eq!(siger.raw().len(), raw_size(idr_dex::ED25519_BIG_CRT_SIG)?);
        assert_eq!(siger.index(), index);
        assert_eq!(siger.ondex(), None);
        let result = signer.verfer().verify(siger.raw(), ser)?;
        assert!(result);

        // Test with invalid code
        let result = Signer::new(Some(&seed), Some(mtr_dex::ED25519N), None);
        assert!(result.is_err());

        Ok(())
    }

    #[test]
    fn test_secp256r1_signer() {
        // Test Secp256r1, default seed
        let signer = Signer::new(None, Some(mtr_dex::ECDSA_256R1_SEED), None).unwrap();
        assert_eq!(signer.code(), mtr_dex::ECDSA_256R1_SEED);
        assert_eq!(
            signer.raw().len(),
            mtr_raw_size(mtr_dex::ECDSA_256R1_SEED).unwrap()
        );
        assert_eq!(signer.verfer().code(), mtr_dex::ECDSA_256R1);
        assert_eq!(
            signer.verfer().raw().len(),
            mtr_raw_size(mtr_dex::ECDSA_256R1).unwrap()
        );

        // Create something to sign and verify
        let ser = b"abcdefghijklmnopqrstuvwxyz0123456789";

        let Sigmat::NonIndexed(cigar) = signer.sign(ser, None, None, None).unwrap() else {
            panic!("Invalid type")
        };
        assert_eq!(cigar.code(), mtr_dex::ECDSA_256R1_SIG);
        assert_eq!(
            cigar.raw().len(),
            mtr_raw_size(mtr_dex::ECDSA_256R1_SIG).unwrap()
        );
        let result = signer.verfer().verify(cigar.raw(), ser).unwrap();
        assert!(result);

        // Test non-default seed
        sodiumoxide::init().unwrap();
        let seed = randombytes::randombytes(32);
        let signer = Signer::new(Some(&seed), Some(mtr_dex::ECDSA_256R1_SEED), None).unwrap();
        assert_eq!(signer.code(), mtr_dex::ECDSA_256R1_SEED);
        assert_eq!(
            signer.raw().len(),
            mtr_raw_size(mtr_dex::ECDSA_256R1_SEED).unwrap()
        );
        assert_eq!(signer.raw(), seed);
        assert_eq!(signer.verfer().code(), mtr_dex::ECDSA_256R1);
        assert_eq!(
            signer.verfer().raw().len(),
            mtr_raw_size(mtr_dex::ECDSA_256R1).unwrap()
        );

        // Test hardcoded seed
        let seed = b"\x9f{\xa8\xa7\xa8C9\x96&\xfa\xb1\x99\xeb\xaa \xc4\x1bG\x11\xc4\xaeSAR\xc9\xbd\x04\x9d\x85)~\x93";
        let signer = Signer::new(Some(seed), Some(mtr_dex::ECDSA_256R1_SEED), None).unwrap();
        assert_eq!(signer.code(), mtr_dex::ECDSA_256R1_SEED);
        assert_eq!(
            signer.raw().len(),
            mtr_raw_size(mtr_dex::ECDSA_256R1_SEED).unwrap()
        );
        assert_eq!(signer.raw(), seed);
        assert_eq!(signer.verfer().code(), mtr_dex::ECDSA_256R1);
        assert_eq!(
            signer.verfer().raw().len(),
            mtr_raw_size(mtr_dex::ECDSA_256R1).unwrap()
        );
        assert_eq!(
            signer.qb64(),
            "QJ97qKeoQzmWJvqxmeuqIMQbRxHErlNBUsm9BJ2FKX6T"
        );
        assert_eq!(
            signer.verfer().qb64(),
            "1AAJA3cK_P2CDlh-_EMFPvyqTPI1POkw-dr14DANx5JEXDCZ"
        );

        // Test vectors from CERSide
        let ser = b"abc";
        let seed = b"\x35\x86\xc9\xa0\x4d\x33\x67\x85\xd5\xe4\x6a\xda\x62\xf0\x54\xc5\xa5\xf4\x32\x3f\x46\xcb\x92\x23\x07\xe0\xe2\x79\xb7\xe5\xf5\x0a";
        let verkey = b"\x03\x16\x99\xbc\xa0\x51\x8f\xa6\x6c\xb3\x5d\x6b\x0a\x92\xf6\x84\x96\x28\x7b\xb6\x64\xe8\xe8\x57\x69\x15\xb8\xea\x9a\x02\x06\x2a\xff";
        let sig = b"\x8c\xfa\xb4\x40\x01\xd2\xab\x4a\xbc\xc5\x96\x8b\xa2\x65\x76\xcd\x51\x9d\x3b\x40\xc3\x35\x21\x73\x9a\x1b\xe8\x2f\xe1\x30\x28\xe1\x07\x90\x08\xa6\x42\xd7\x3f\x36\x8c\x96\x32\xff\x01\x64\x03\x18\x08\x85\xb8\xa4\x97\x76\xbe\x9c\xe4\xd7\xc5\xe7\x05\xda\x51\x23";

        let signerqb64 = "QDWGyaBNM2eF1eRq2mLwVMWl9DI_RsuSIwfg4nm35fUK";
        let verferqb64 = "1AAJAxaZvKBRj6Zss11rCpL2hJYoe7Zk6OhXaRW46poCBir_";
        let cigarqb64 = "0ICM-rRAAdKrSrzFlouiZXbNUZ07QMM1IXOaG-gv4TAo4QeQCKZC1z82jJYy_wFkAxgIhbikl3a-nOTXxecF2lEj";

        let signer = Signer::new(Some(seed), Some(mtr_dex::ECDSA_256R1_SEED), None).unwrap();
        let Sigmat::NonIndexed(cigar) = signer.sign(ser, None, None, None).unwrap() else {
            panic!("Invalid type")
        };

        assert_eq!(signer.code(), mtr_dex::ECDSA_256R1_SEED);
        assert_eq!(
            signer.raw().len(),
            mtr_raw_size(mtr_dex::ECDSA_256R1_SEED).unwrap()
        );
        assert_eq!(signer.raw(), seed);
        assert_eq!(signer.qb64(), signerqb64);

        assert_eq!(signer.verfer().code(), mtr_dex::ECDSA_256R1);
        assert_eq!(
            signer.verfer().raw().len(),
            mtr_raw_size(mtr_dex::ECDSA_256R1).unwrap()
        );
        assert_eq!(signer.verfer().raw(), verkey);
        assert_eq!(signer.verfer().qb64(), verferqb64);

        assert_eq!(cigar.code(), mtr_dex::ECDSA_256R1_SIG);
        assert_eq!(
            cigar.raw().len(),
            mtr_raw_size(mtr_dex::ECDSA_256R1_SIG).unwrap()
        );
        assert!(signer.verfer().verify(cigar.raw(), ser).unwrap());
        assert!(signer.verfer().verify(sig, ser).unwrap());

        let cigar =
            Cigar::new(Some(sig), Some(mtr_dex::ECDSA_256R1_SIG), None, None, None).unwrap();
        assert_eq!(cigar.qb64(), cigarqb64);
    }
}
