use std::any::Any;
use sodiumoxide::crypto::box_::SecretKey;
use sodiumoxide::crypto::sealedbox;
use sodiumoxide::crypto::sign::ed25519;
use crate::cesr::{mtr_dex, BaseMatter, Parsable};
use crate::cesr::signing::cipher::Cipher;
use crate::cesr::signing::{cix_var_qb2_dex, cix_var_strm_dex, ed25519_sk_to_x25519_sk, Salter, Signer};
use crate::errors::MatterError;
use crate::Matter;

/// Decrypter is a Matter subclass with methods to decrypt plain text from a
/// cipher text of a fully qualified (qb64) private key/seed where private
/// key/seed is the plain text. Decrypter uses asymmetric (public, private) key
/// decryption of the cipher text using its .raw as the decrypting (private) key
/// and its .code to indicate the cipher suite for the decryption operation.
#[derive(Debug, Clone)]
pub struct Decrypter {
    base: BaseMatter,
}

impl Decrypter {
    /// Create a new Decrypter instance
    ///
    /// # Arguments
    ///
    /// * `raw` - Optional raw binary of the private decryption key
    /// * `code` - Optional derivation code for private decryption key
    /// * `qb64b` - Optional qualified base64 binary of key material
    /// * `qb64` - Optional qualified base64 string of key material
    /// * `qb2` - Optional qualified binary of key material
    /// * `seed` - Optional seed for deriving the decryption key
    ///
    /// # Returns
    ///
    /// * `Result<Self, MatterError>` - New Decrypter instance or error
    pub fn new(
        raw: Option<&[u8]>,
        code: Option<&str>,
        seed: Option<&[u8]>,
    ) -> Result<Self, MatterError> {
        let code = code.unwrap_or(mtr_dex::X25519_PRIVATE);

        let raw = match raw {
            Some(r) => r,
            None => {
                if seed.is_some() {
                    // Derive decryption key from signing key
                    let signer = Signer::from_qb64b(&mut seed.unwrap().to_vec(), None)?;

                    if signer.code() != mtr_dex::ED25519_SEED { // Ed25519_Seed code
                        return Err(MatterError::InvalidCode(format!(
                            "Unsupported signing seed derivation code = {}",
                            signer.code()
                        )));
                    }

                    // sigkey is raw seed + raw verkey
                    let mut sigkey = Vec::new();
                    sigkey.extend_from_slice(signer.raw());
                    sigkey.extend_from_slice(signer.verfer().raw());

                    // Convert signing key to encryption key
                    let ed_sk = ed25519::SecretKey::from_slice(&sigkey).unwrap();
                    let sk = ed25519_sk_to_x25519_sk(&ed_sk)?;
                    &sk.as_ref().to_vec()
                }
                else {
                    return Err(MatterError::ValueError("Either seed or raw must be provided".to_string()));
                }
            }
        };

        let base = BaseMatter::new(Some(&raw), Some(code), None, None)?;

        if base.code() != mtr_dex::X25519_PRIVATE {
            return Err(MatterError::InvalidCode(format!(
                "Unsupported decrypter code = {}",
                base.code()
            )));
        }


        Ok(Decrypter {
            base,
        })
    }

    /// Create a Decrypter from a qualified base64 string
    pub fn from_qb64(qb64: &str) -> Result<Self, MatterError> {
        let base = BaseMatter::from_qb64(qb64)?;
        let decrypter = Decrypter { base };

        if decrypter.code() != mtr_dex::X25519_PRIVATE {
            return Err(MatterError::InvalidCode(format!(
                "Unsupported decrypter code = {}",
                decrypter.code()
            )));
        }

        Ok(decrypter)
    }

    /// Decrypt a cipher text and return plain text
    ///
    /// # Arguments
    ///
    /// * `cipher` - Optional Cipher instance
    /// * `qb64` - Optional qualified base64 string of cipher text
    /// * `qb2` - Optional qualified binary of cipher text
    /// * `transferable` - Modifier for returned instance creation when applicable
    /// * `bare` - If true, returns raw bytes instead of a Matter instance
    ///
    /// # Returns
    ///
    /// * `Result<Box<dyn Any>, MatterError>` - Decrypted data as specified type or error
    pub fn decrypt(
        &self,
        cipher: Option<&Cipher>,
        qb64: Option<&str>,
        qb2: Option<&[u8]>,
        transferable: Option<bool>,
        bare: Option<bool>,
    ) -> Result<Box<dyn Any>, MatterError> {
        let transferable = transferable.unwrap_or(false);
        let bare = bare.unwrap_or(false);

        let cipher = if let Some(c) = cipher {
            c.clone()
        } else if let Some(q) = qb64 {
            Cipher::from_qb64(q)?
        } else if let Some(q) = qb2 {
            let mut qb2_vec = q.to_vec();
            Cipher::from_qb2(&mut qb2_vec, Some(true))?
        } else {
            return Err(MatterError::EmptyMaterialError("qb64, qb2, or cipher must be provided".to_string()));
        };

        // X25519 is currently the only supported cipher suite
        self.decrypt_x25519(&cipher, transferable, bare)
    }

    /// Decrypt using X25519 sealed box
    fn decrypt_x25519(
        &self,
        cipher: &Cipher,
        transferable: bool,
        bare: bool,
    ) -> Result<Box<dyn Any>, MatterError> {
        // Calculate public key from private key
        let private_key = SecretKey::from_slice(self.raw())
            .ok_or_else(|| MatterError::InvalidKey("Invalid X25519 private key".to_string()))?;
        let public_key = private_key.public_key();

        // Decrypt the cipher text
        let mut plain = sealedbox::open(
            cipher.raw(),
            &public_key,
            &private_key,
        ).map_err(|_| MatterError::VerificationError("Decryption failed".to_string()))?;

        if bare {
            return Ok(Box::new(plain));
        }

        // Determine the appropriate class based on cipher code
        match cipher.code() {
            mtr_dex::X25519_CIPHER_SALT => {
                if cix_var_qb2_dex::TUPLE.contains(&cipher.code()) {
                    let salter = Salter::from_qb2(&mut plain, None)?;
                    Ok(Box::new(salter))
                } else {
                    let salter = Salter::from_qb64b(&mut plain, None)?;
                    Ok(Box::new(salter))
                }
            }
            mtr_dex::X25519_CIPHER_SEED => {
                if cix_var_qb2_dex::TUPLE.contains(&cipher.code()) {
                    let signer = Signer::from_qb2(&mut plain, None)?;
                    Ok(Box::new(signer))
                } else {
                    let signer = Signer::from_qb64b_and_transferable(&mut plain, None, transferable)?;
                    Ok(Box::new(signer))
                }
            }
            code if cix_var_strm_dex::TUPLE.contains(&code) => {
                // Handle variable length QB2 data
                // let mut qb2_data = plain.clone();
                // let streamer = Streamer::from_qb2(&mut qb2_data, Some(true))?;
                // Ok(Box::new(streamer))
                Err(MatterError::InvalidCode(format!(
                    "Stream cipher code = {} not supported yet",
                    cipher.code()
                )))
            }
            _ => Err(MatterError::InvalidCode(format!(
                "Unsupported cipher code = {}",
                cipher.code()
            ))),
        }
    }
}

impl Parsable for Decrypter {
    fn from_qb64b(data: &mut Vec<u8>, strip: Option<bool>) -> Result<Self, MatterError> {
        let base = BaseMatter::from_qb64b(data, strip)?;
        if base.code() != mtr_dex::X25519_PRIVATE {
            return Err(MatterError::InvalidCode(format!(
                "Unsupported decrypter code = {}",
                base.code()
            )));
        }

        Ok(Decrypter { base })
    }

    fn from_qb2(data: &mut Vec<u8>, strip: Option<bool>) -> Result<Self, MatterError> {
        let base = BaseMatter::from_qb2(data, strip)?;
        if base.code() != mtr_dex::X25519_PRIVATE {
            return Err(MatterError::InvalidCode(format!(
                "Unsupported decrypter code = {}",
                base.code()
            )));
        }

        Ok(Decrypter { base })
    }
}

impl Matter for Decrypter {
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
    use sodiumoxide::crypto::sign;
    use crate::cesr::signing::ed25519_pk_to_x25519_pk;
    use crate::cesr::signing::encrypter::Encrypter;

    #[test]
    fn test_decrypter() {
        // Initialize sodiumoxide
        sodiumoxide::init().expect("Sodium initialization failed");

        // Create seed for testing
        let seed = [
            0x18, 0x3B, 0x30, 0xC4, 0x0F, 0x2A, 0x76, 0x46, 0xFA, 0xE3, 0xA2, 0x45, 0x65, 0x65,
            0x1F, 0x96, 0x6F, 0xCE, 0x29, 0x47, 0x85, 0xE3, 0x58, 0x86, 0xDA, 0x04, 0xF0, 0xDC,
            0xDE, 0x06, 0xC0, 0x2B,
        ];

        // Create signer from seed
        let signer = Signer::new(Some(&seed), Some(mtr_dex::ED25519_SEED), Some(true)).unwrap();
        assert_eq!(signer.verfer().code(), mtr_dex::ED25519);
        assert!(signer.verfer().is_transferable()); // default
        let seedqb64b = signer.qb64b();
        assert_eq!(seedqb64b, b"ABg7MMQPKnZG-uOiRWVlH5ZvzilHheNYhtoE8NzeBsAr");

        // Verify Matter basic functionality using same seed
        let matter_seedqb64b = BaseMatter::new(Some(&seed), Some(mtr_dex::ED25519_SEED), None, None).unwrap().qb64b();
        assert_eq!(seedqb64b, matter_seedqb64b);

        // Create salt for testing
        let salt_raw = [
            0x36, 0x08, 0x64, 0x0D, 0xA1, 0xBB, 0x39, 0x8D, 0x70, 0x8D, 0xA0, 0xC0, 0x13, 0x4A,
            0x87, 0x72,
        ];

        // Create salter
        let salter = Salter::new(Some(&salt_raw), Some(mtr_dex::SALT_128), None).unwrap();
        assert_eq!(salter.code(), mtr_dex::SALT_128);
        let saltqb64b = salter.qb64b();
        assert_eq!(saltqb64b, b"0AA2CGQNobs5jXCNoMATSody");

        // Verify Matter basic functionality using same salt
        let matter_saltqb64b = BaseMatter::new(Some(&salt_raw), Some(mtr_dex::SALT_128), None, None).unwrap().qb64b();
        assert_eq!(saltqb64b, matter_saltqb64b);

        // Create cryptographic seed for key generation
        let cryptseed = [
            0x68, 0x2C, 0x23, 0x7C, 0x8A, 0x70, 0x22, 0x12, 0xC4, 0x33, 0x74, 0x32, 0xA6, 0xE1,
            0x18, 0x19, 0xF0, 0x66, 0x32, 0x2C, 0x79, 0xC4, 0xC2, 0x31, 0x40, 0xF5, 0x40, 0x15,
            0x2E, 0xA2, 0x1A, 0xCF,
        ];

        // Create cryptsigner
        let cryptsigner = Signer::new(Some(&cryptseed), Some(mtr_dex::ED25519_SEED), Some(true)).unwrap();

        // Generate key pairs
        let seed_key = sign::Seed::from_slice(&cryptseed).unwrap();
        let (verkey, sigkey) = sign::keypair_from_seed(&seed_key);

        // Convert ed25519 keys to x25519 keys
        let ed_pk = sign::PublicKey::from_slice(verkey.as_ref()).unwrap();
        let ed_sk = sign::SecretKey::from_slice(sigkey.as_ref()).unwrap();

        let pubkey = ed25519_pk_to_x25519_pk(&ed_pk).unwrap();
        let prikey = ed25519_sk_to_x25519_sk(&ed_sk).unwrap();

        // Test empty constructor
        let result = Decrypter::new(None, None, None);
        assert!(result.is_err());

        // Create encrypter with public key
        let encrypter = Encrypter::new(Some(pubkey.as_ref()), Some(mtr_dex::X25519), None).unwrap();
        assert_eq!(encrypter.code(), mtr_dex::X25519);
        assert_eq!(encrypter.qb64(), "CAF7Wr3XNq5hArcOuBJzaY6Nd23jgtUVI6KDfb3VngkR");
        assert_eq!(encrypter.raw(), pubkey.as_ref());

        // Encrypt seed
        let seedcipher = encrypter.encrypt(Some(&seedqb64b), None, Some(mtr_dex::X25519_CIPHER_SEED)).unwrap();
        assert_eq!(seedcipher.code(), mtr_dex::X25519_CIPHER_SEED);

        // Create decrypter from private key
        let decrypter = Decrypter::new(Some(prikey.as_ref()), Some(mtr_dex::X25519_PRIVATE), None).unwrap();
        assert_eq!(decrypter.code(), mtr_dex::X25519_PRIVATE);
        assert_eq!(decrypter.qb64(), "OLCFxqMz1z1UUS0TEJnvZP_zXHcuYdQsSGBWdOZeY5VQ");
        assert_eq!(decrypter.raw(), prikey.as_ref());

        // Decrypt seed cipher using qb64
        let designer = decrypter.decrypt(
            None,
            Some(&seedcipher.qb64()),
            None,
            Some(signer.verfer().is_transferable()),
            Some(false)
        ).unwrap();

        let designer = designer.downcast_ref::<Signer>().unwrap();
        assert_eq!(designer.qb64b(), seedqb64b);
        assert_eq!(designer.code(), mtr_dex::ED25519_SEED);
        assert_eq!(designer.verfer().code(), mtr_dex::ED25519);
        assert!(designer.verfer().is_transferable());

        // Test bare decryption returns plain bytes not instance
        let plain = decrypter.decrypt(
            None,
            Some(&seedcipher.qb64()),
            None,
            Some(signer.verfer().is_transferable()),
            Some(true)
        ).unwrap();

        let plain = plain.downcast_ref::<Vec<u8>>().unwrap();
        assert_eq!(plain, &seedqb64b);

        // Decrypt seed cipher using cipher
        let designer = decrypter.decrypt(
            Some(&seedcipher),
            None,
            None,
            Some(signer.verfer().is_transferable()),
            Some(false)
        ).unwrap();

        let designer = designer.downcast_ref::<Signer>().unwrap();
        assert_eq!(designer.qb64b(), seedqb64b);
        assert_eq!(designer.code(), mtr_dex::ED25519_SEED);
        assert_eq!(designer.verfer().code(), mtr_dex::ED25519);
        assert!(designer.verfer().is_transferable());

        // Encrypt salt
        let saltcipher = encrypter.encrypt(Some(saltqb64b.as_ref()), None, Some(mtr_dex::X25519_CIPHER_SALT)).unwrap();
        assert_eq!(saltcipher.code(), mtr_dex::X25519_CIPHER_SALT);

        // Decrypt salt cipher using qb64
        let desalter = decrypter.decrypt(
            None,
            Some(&saltcipher.qb64()),
            None,
            None,
            Some(false)
        ).unwrap();

        let desalter = desalter.downcast_ref::<Salter>().unwrap();
        assert_eq!(desalter.qb64b(), saltqb64b);
        assert_eq!(desalter.code(), mtr_dex::SALT_128);

        // Test bare decryption returns plain bytes not instance
        let plain = decrypter.decrypt(
            None,
            Some(&saltcipher.qb64()),
            None,
            None,
            Some(true)
        ).unwrap();

        let plain = plain.downcast_ref::<Vec<u8>>().unwrap();
        assert_eq!(plain, &saltqb64b);

        // Decrypt salt cipher using cipher
        let desalter = decrypter.decrypt(
            Some(&saltcipher),
            None,
            None,
            None,
            Some(false)
        ).unwrap();

        let desalter = desalter.downcast_ref::<Salter>().unwrap();
        assert_eq!(desalter.qb64b(), saltqb64b);
        assert_eq!(desalter.code(), mtr_dex::SALT_128);

        // Use previously stored fully qualified seed cipher with different nonce
        let cipherseed = "PM9jOGWNYfjM_oLXJNaQ8UlFSAV5ACjsUY7J16xfzrlpc9Ve3A5WYrZ4o_NHtP5lhp78Usspl9fyFdnCdItNd5JyqZ6dt8SXOt6TOqOCs-gy0obrwFkPPqBvVkEw";
        let designer = decrypter.decrypt(
            None,
            Some(cipherseed),
            None,
            Some(signer.verfer().is_transferable()),
            Some(false)
        ).unwrap();

        let designer = designer.downcast_ref::<Signer>().unwrap();
        assert_eq!(designer.qb64b(), seedqb64b);
        assert_eq!(designer.code(), mtr_dex::ED25519_SEED);
        assert_eq!(designer.verfer().code(), mtr_dex::ED25519);

        // Use previously stored fully qualified salt cipher with different nonce
        let ciphersalt = "1AAHjlR2QR9J5Et67Wy-ZaVdTryN6T6ohg44r73GLRPnHw-5S3ABFkhWyIwLOI6TXUB_5CT13S8JvknxLxBaF8ANPK9FSOPD8tYu";
        let desalter = decrypter.decrypt(
            None,
            Some(ciphersalt),
            None,
            None,
            Some(false)
        ).unwrap();

        let desalter = desalter.downcast_ref::<Salter>().unwrap();
        assert_eq!(desalter.qb64b(), saltqb64b);
        assert_eq!(desalter.code(), mtr_dex::SALT_128);

        // Create new decrypter using seed parameter to init prikey
        let decrypter = Decrypter::new(
            None,
            None,
            Some(cryptsigner.qb64b().as_ref())
        ).unwrap();

        assert_eq!(decrypter.code(), mtr_dex::X25519_PRIVATE);
        assert_eq!(decrypter.qb64(), "OLCFxqMz1z1UUS0TEJnvZP_zXHcuYdQsSGBWdOZeY5VQ");
        assert_eq!(decrypter.raw(), prikey.as_ref());

        // Decrypt ciphersalt with new decrypter
        let desalter = decrypter.decrypt(
            None,
            Some(&saltcipher.qb64()),
            None,
            None,
            Some(false)
        ).unwrap();

        let desalter = desalter.downcast_ref::<Salter>().unwrap();
        assert_eq!(desalter.qb64b(), saltqb64b);
        assert_eq!(desalter.code(), mtr_dex::SALT_128);
    }

    #[test]
    fn test_decrypter_parsable() -> Result<(), MatterError> {
        // Initialize sodiumoxide
        sodiumoxide::init().expect("Sodium initialization failed");

        // Generate key material
        let seed_key = sign::gen_keypair();
        let prikey = ed25519_sk_to_x25519_sk(&seed_key.1)?;

        // Create decrypter
        let decrypter = Decrypter::new(Some(prikey.as_ref()), Some(mtr_dex::X25519_PRIVATE), None)?;

        // Test parsing from qb64
        let qb64 = decrypter.qb64();
        let parsed_decrypter = Decrypter::from_qb64(&qb64)?;
        assert_eq!(parsed_decrypter.raw(), decrypter.raw());

        // Test parsing from qb64b
        let mut qb64b = decrypter.qb64b();
        let parsed_decrypter = Decrypter::from_qb64b(&mut qb64b, Some(true))?;
        assert_eq!(parsed_decrypter.raw(), decrypter.raw());

        // Test parsing from qb2
        // TODO: qb2
        // let mut qb2 = decrypter.qb2();
        // let parsed_decrypter = Decrypter::from_qb2(&mut qb2, Some(true))?;
        // assert_eq!(parsed_decrypter.raw(), decrypter.raw());

        Ok(())
    }

    #[test]
    fn test_decrypter_error_cases() {
        // Test empty constructor error
        let result = Decrypter::new(None, None, None);
        assert!(result.is_err());

        // Test invalid key material
        let invalid_key = [0u8; 31]; // X25519 keys should be 32 bytes
        let result = Decrypter::new(Some(&invalid_key), Some(mtr_dex::X25519_PRIVATE), None);
        assert!(result.is_err());

        // Test invalid code
        let valid_key = [0u8; 32];
        let result = Decrypter::new(Some(&valid_key), Some(mtr_dex::ED25519), None);
        assert!(result.is_err());

        // Test invalid qb64 format
        let result = Decrypter::from_qb64("invalid-qb64-format");
        assert!(result.is_err());
    }
}