use std::any::Any;
use sodiumoxide::crypto::sign::ed25519;
use crate::cesr::{mtr_dex, BaseMatter, Parsable};
use crate::errors::MatterError;
use crate::Matter;

use secp256k1::{Secp256k1, Message, PublicKey};
use secp256k1::ecdsa::Signature;
use p256::{
    ecdsa::{signature::Verifier, Signature as p256Signature, VerifyingKey}
};
use sha2::{Digest, Sha256};

///  Verfer is Matter subclass with method to verify signature of serialization
///  using the .raw as verifier key and .code for signature cipher suite.
#[derive(Debug, Clone)]
pub struct Verfer {
    base: BaseMatter,
}

impl Verfer {
    /// Creates a new `Verfer` instance from a QB64-encoded string.
    /// This method calls `BaseMatter::from_qb64` and verifies the code is supported.
    pub fn from_qb64(qb64: &str) -> Result<Self, MatterError> {
        let base = BaseMatter::from_qb64(qb64)?;

        // Validate the code is supported
        if ![
            mtr_dex::ED25519N,
            mtr_dex::ED25519,
            mtr_dex::ECDSA_256R1N,
            mtr_dex::ECDSA_256R1,
            mtr_dex::ECDSA_256K1N,
            mtr_dex::ECDSA_256K1,
        ].contains(&base.code()) {
            return Err(MatterError::UnsupportedCodeError(String::from(base.code())));
        }

        Ok(Verfer { base })
    }

    pub fn new(code: Option<&[u8]>, raw: Option<&str>) -> Result<Self, MatterError> {
        let verfer = Self { base: BaseMatter::new(code, raw, None, None)? };

        // Validate the code is supported
        if ![
            mtr_dex::ED25519N,
            mtr_dex::ED25519,
            mtr_dex::ECDSA_256R1N,
            mtr_dex::ECDSA_256R1,
            mtr_dex::ECDSA_256K1N,
            mtr_dex::ECDSA_256K1,
        ].contains(&verfer.code()) {
            return Err(MatterError::UnsupportedCodeError(String::from(verfer.code())));
        }

        Ok(verfer)
    }

    // Public method that dispatches to the appropriate implementation
    pub fn verify(&self, sig: &[u8], ser: &[u8]) -> Result<bool, MatterError> {
        match self.code() {
            code if code == mtr_dex::ED25519N || code == mtr_dex::ED25519 => {
                self.ed25519_verify(sig, ser)
            },
            code if code == mtr_dex::ECDSA_256R1N || code == mtr_dex::ECDSA_256R1 => {
                self.secp256r1_verify(sig, ser)
            },
            code if code == mtr_dex::ECDSA_256K1N || code == mtr_dex::ECDSA_256K1 => {
                self.secp256k1_verify(sig, ser)
            },
            // This should never happen because we validate in the constructor
            _ => Err(MatterError::UnsupportedCodeError(String::from(self.code()))),
        }
    }

    // Private implementation methods
    fn ed25519_verify(&self, sig: &[u8], ser: &[u8]) -> Result<bool, MatterError> {
        // Ed25519 public key must be 32 bytes
        if self.raw().len() != ed25519::PUBLICKEYBYTES {
            return Err(MatterError::InvalidKeyLength {
                expected: ed25519::PUBLICKEYBYTES,
                actual: self.raw().len()
            });
        }

        // Ed25519 signature must be 64 bytes
        if sig.len() != ed25519::SIGNATUREBYTES {
            return Err(MatterError::InvalidSignatureLength {
                expected: ed25519::SIGNATUREBYTES,
                actual: sig.len()
            });
        }

        // Convert raw key bytes to sodiumoxide PublicKey
        let pk = match ed25519::PublicKey::from_slice(&self.raw()) {
            Some(key) => key,
            None => return Err(MatterError::VerificationError("Invalid public key format".to_string())),
        };

        // Convert signature bytes to sodiumoxide Signature
        let signature = match ed25519::Signature::from_bytes(sig) {
            Ok(sig) => sig,
            Err(_) => return Err(MatterError::VerificationError("Invalid signature format".to_string())),
        };
        // Verify the signature
        let result = ed25519::verify_detached(&signature, ser, &pk);

        Ok(result)
    }


    fn secp256r1_verify(&self, sig: &[u8], ser: &[u8]) -> Result<bool, MatterError> {
        // P-256 public keys are typically 33 bytes (compressed) or 65 bytes (uncompressed)
        if self.raw().len() != 33 && self.raw().len() != 65 {
            return Err(MatterError::InvalidKeyLength {
                expected: 33, // We can expect compressed keys as standard
                actual: self.raw().len()
            });
        }

        // Parse the verifying key from SEC1 encoded public key bytes
        let verifying_key = VerifyingKey::from_sec1_bytes(&self.raw())
            .map_err(|e| MatterError::Secp256r1Error(format!("Invalid public key: {}", e)))?;

        // For P-256 ECDSA signatures, we need to handle different formats

        // Try to parse the signature as DER format first
        let signature_result = p256Signature::from_bytes(sig.into());

        // If DER parsing fails, try ASN.1 format
        let signature = match signature_result {
            Ok(sig) => sig,
            Err(_) => {
                // If not DER, try ASN.1
                p256Signature::try_from(sig)
                    .map_err(|e| MatterError::Secp256r1Error(format!("Invalid signature format: {}", e)))?
            }
        };

        // Verify the signature against the hash
        match verifying_key.verify(ser, &signature) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false), // Signature verification failed but the function succeeded
        }
    }


    fn secp256k1_verify(&self, sig: &[u8], ser: &[u8]) -> Result<bool, MatterError> {
        // Create a secp256k1 context for verification only
        let secp = Secp256k1::verification_only();

        // SECP256K1 public keys are typically 33 bytes (compressed) or 65 bytes (uncompressed)
        // Check that we have a valid public key length
        if self.raw().len() != 33 && self.raw().len() != 65 {
            return Err(MatterError::InvalidKeyLength {
                expected: 33, // We can expect compressed keys as standard
                actual: self.raw().len()
            });
        }

        // Parse the public key from self.raw
        let public_key = PublicKey::from_slice(&self.raw())
            .map_err(|e| MatterError::Secp256k1Error(format!("Invalid public key: {}", e)))?;

        // For ECDSA signatures with secp256k1, we typically expect DER or compact format
        // Compact is 64 bytes, DER can vary but is typically ~70-72 bytes

        // Attempt to parse as compact first (most common in many systems)
        let signature = if sig.len() == 64 {
            Signature::from_compact(sig)
                .map_err(|e| MatterError::Secp256k1Error(format!("Invalid compact signature: {}", e)))?
        } else {
            // Try as DER format
            Signature::from_der(sig)
                .map_err(|e| MatterError::Secp256k1Error(format!("Invalid DER signature: {}", e)))?
        };

        // ECDSA requires a 32-byte message digest
        // Hash the serialized data to get a 32-byte digest
        let mut hasher = Sha256::new();
        hasher.update(ser);
        let result = hasher.finalize();
        let message_hash: [u8; 32] = result.into();


        // Create a Message object from the 32-byte hash
        let message = Message::from_digest(message_hash);

        // Verify the signature
        match secp.verify_ecdsa(&message, &signature, &public_key) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false), // Verification failed but function succeeded
        }
    }

}

impl Parsable for Verfer {
    fn from_qb64b(data: &mut Vec<u8>, strip: Option<bool>) -> Result<Self, MatterError> {
        let base = BaseMatter::from_qb64b(data, strip)?;
        if ![
            mtr_dex::ED25519N,
            mtr_dex::ED25519,
            mtr_dex::ECDSA_256R1N,
            mtr_dex::ECDSA_256R1,
            mtr_dex::ECDSA_256K1N,
            mtr_dex::ECDSA_256K1,
        ].contains(&base.code()) {
            return Err(MatterError::UnsupportedCodeError(String::from(base.code())));
        }

        Ok(Verfer {
            base
        })
    }


    fn from_qb2(data: &mut Vec<u8>, strip: Option<bool>) -> Result<Self, MatterError> {
        let base = BaseMatter::from_qb2(data, strip)?;
        if ![
            mtr_dex::ED25519N,
            mtr_dex::ED25519,
            mtr_dex::ECDSA_256R1N,
            mtr_dex::ECDSA_256R1,
            mtr_dex::ECDSA_256K1N,
            mtr_dex::ECDSA_256K1,
        ].contains(&base.code()) {
            return Err(MatterError::UnsupportedCodeError(String::from(base.code())));
        }

        Ok(Verfer {
            base
        })
    }
}

impl Matter for Verfer {
    fn code(&self) -> &str { self.base.code() }
    fn raw(&self) -> &[u8] { self.base.raw() }
    fn qb64(&self) -> String { self.base.qb64() }
    fn qb64b(&self) -> Vec<u8> { self.base.qb64b() }
    fn qb2(&self) -> Vec<u8> { self.base.qb2() }
    fn soft(&self) -> &str { self.base.soft() }
    fn full_size(&self) -> usize { self.base.full_size() }
    fn size(&self) -> usize { self.base.size() }
    fn is_transferable(&self) -> bool { self.base.is_transferable() }
    fn is_digestive(&self) -> bool { self.base.is_digestive() }
    fn is_prefixive(&self) -> bool { self.base.is_prefixive() }
    fn is_special(&self) -> bool { self.base.is_special() }
    fn as_any(&self) -> &dyn Any { self }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sodiumoxide::crypto::sign::ed25519;
    use p256::{ecdsa::{SigningKey, signature::Signer}};
    use rand_core::OsRng;
    use secp256k1::{rand, Secp256k1, SecretKey, PublicKey};
    use sha2::{Sha256, Digest};

    #[test]
    fn test_verfer_ed25519() {
        // Initialize sodiumoxide
        sodiumoxide::init().expect("Sodium initialization failed");

        // Generate random seed and keypair
        let (public_key, secret_key) = ed25519::gen_keypair();
        let verkey = public_key.as_ref();

        // Test EmptyMaterialError
        let empty_result = Verfer::new(None, Some(mtr_dex::ED25519N));
        assert!(matches!(empty_result, Err(MatterError::TypeError(_))));

        // Test with Ed25519N code
        let verfer = Verfer::new(Some(verkey), Some(mtr_dex::ED25519N)).unwrap();
        assert_eq!(verfer.raw(), verkey);
        assert_eq!(verfer.code(), mtr_dex::ED25519N);

        // Create something to sign and verify
        let ser = b"abcdefghijklmnopqrstuvwxyz0123456789";

        // Sign the message
        let sig = ed25519::sign_detached(ser, &secret_key);

        // Verify the signature
        let result = verfer.verify(sig.as_ref(), ser).unwrap();
        assert!(result);

        // Test with Ed25519 code
        let verfer = Verfer::new(Some(verkey), Some(mtr_dex::ED25519)).unwrap();
        assert_eq!(verfer.raw(), verkey);
        assert_eq!(verfer.code(), mtr_dex::ED25519);

        // Verify the signature again
        let result = verfer.verify(sig.as_ref(), ser).unwrap();
        assert!(result);

        // Test with invalid code
        let blake_result = Verfer::new(Some(verkey), Some(mtr_dex::BLAKE3_256));
        assert!(matches!(blake_result, Err(MatterError::UnsupportedCodeError(_))));
    }

    #[test]
    fn test_secp256r1_verfer() {
        // Initialize sodiumoxide
        sodiumoxide::init().expect("Sodium initialization failed");

        let signing_key = SigningKey::random(&mut OsRng);

        // Get the public key in compressed format (equivalent to CompressedPoint in Python)
        let p256_public_key = signing_key.verifying_key();
        let verkey = p256_public_key.to_encoded_point(true).as_bytes().to_vec();

        // Create Verfer with secp256r1
        let verfer = Verfer::new(Some(&verkey), Some(mtr_dex::ECDSA_256R1))
            .expect("Failed to create verfer");

        // Verify the verfer properties
        assert_eq!(verfer.raw(), &(*verkey));
        assert_eq!(verfer.code(), mtr_dex::ECDSA_256R1);

        // Message to sign
        let ser = b"abcdefghijklmnopqrstuvwxyz0123456789";

        // Sign the message
        // Note: p256 library automatically hashes using SHA-256 when signing
        let signature: p256Signature = signing_key.sign(ser);
        let result = match p256_public_key.verify(ser, &signature) {
            Ok(_) => true,
            Err(_) => false,
        };
        assert!(result);


        // Convert the ASN.1 DER signature to raw R and S values
        // (equivalent to decode_dss_signature in Python)
        let der_bytes = signature.to_bytes();

        // Also create a raw signature from R and S components
        // This is equivalent to the Python code creating sig from r and s
        // Extract the r and s values
        let r = signature.r().to_bytes();
        let s = signature.s().to_bytes();

        let mut raw_sig = Vec::with_capacity(64);
        raw_sig.extend_from_slice(&r);
        raw_sig.extend_from_slice(&s);

        // Verify the signature
        let result = verfer.verify(&raw_sig, ser)
            .expect("Verification failed with error");
        assert!(result);

        // Test negative case
        let result = verfer.verify(&der_bytes, b"ABC")
            .expect("Verification failed with error");
        assert!(!result);

        // Create Verfer with secp256r1
        let verfer = Verfer::new(Some(&verkey), Some(mtr_dex::ECDSA_256R1N))
            .expect("Failed to create verfer");

        // Verify the verfer properties
        assert_eq!(verfer.raw(), &(*verkey));
        assert_eq!(verfer.code(), mtr_dex::ECDSA_256R1N);
    }

    #[test]
    fn test_verfer_secp256k1() {
        // Create a new secp256k1 context
        let secp = Secp256k1::new();

        // Generate random secret key
        let mut rng = rand::thread_rng();
        let secret_key = SecretKey::new(&mut rng);

        // Get the public key in compressed format (equivalent to X962 compressed point format)
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);
        let verkey = public_key.serialize();

        // Create verfer with the compressed public key
        let verfer = Verfer::new(Some(&verkey.to_vec()), Some(mtr_dex::ECDSA_256K1)).unwrap();

        assert_eq!(verfer.raw(), verkey.to_vec());
        assert_eq!(verfer.code(), mtr_dex::ECDSA_256K1);

        // Message to sign
        let ser = b"abcdefghijklmnopqrstuvwxyz0123456789";

        // Hash the message with SHA-256
        let mut hasher = Sha256::new();
        hasher.update(ser);
        let digest = hasher.finalize();
        let digest: [u8; 32] = digest.into();

        // Sign the message hash with the secret key
        let message = Message::from_digest(digest);
        let signature = secp.sign_ecdsa(&message, &secret_key);

        // Get DER format for signature (for testing DER rejection)
        let der_sig = signature.serialize_der();

        // Convert to r+s format (each 32 bytes)
        let ser_sig = signature.serialize_compact();

        // Verify signature
        let result = verfer.verify(&ser_sig, ser).unwrap();
        assert!(result);

        // Try verifying with wrong message
        let wrong_message = b"ABC";
        let result = verfer.verify(&der_sig, wrong_message);
        assert!(result.is_err() || !result.unwrap());

        // Test with ECDSA_256k1N
        // Generate new random keys
        let secret_key = SecretKey::new(&mut rng);
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);
        let verkey = public_key.serialize();

        // Create verfer with the compressed public key using ECDSA_256k1N
        let verfer = Verfer::new(Some(&verkey.to_vec()), Some(mtr_dex::ECDSA_256K1N)).unwrap();

        assert_eq!(verfer.raw(), verkey.to_vec());
        assert_eq!(verfer.code(), mtr_dex::ECDSA_256K1N);

        // Sign the message hash with the secret key
        let mut hasher = Sha256::new();
        hasher.update(ser);
        let digest = hasher.finalize();
        let digest: [u8; 32] = digest.into();

        let message = Message::from_digest(digest);
        let signature = secp.sign_ecdsa(&message, &secret_key);

        // Get DER format for signature (for testing DER rejection)
        let der_sig = signature.serialize_der();

        // Convert to r+s format (each 32 bytes)
        let ser_sig = signature.serialize_compact();

        // Verify signature
        let result = verfer.verify(&ser_sig, ser).unwrap();
        assert!(result);

        // Try verifying with wrong message
        let wrong_message = b"ABC";
        let result = verfer.verify(&der_sig, wrong_message);
        assert!(result.is_err() || !result.unwrap());
    }
}
