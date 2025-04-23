use crate::cesr::signing::cipher::Cipher;
use crate::cesr::signing::{
    cix_all_qb64_dex, cix_var_qb2_dex, cix_var_strm_dex, ed25519_pk_to_x25519_pk, Signer,
};
use crate::cesr::verfer::Verfer;
use crate::cesr::{mtr_dex, BaseMatter, Parsable};
use crate::errors::MatterError;
use crate::Matter;
use sodiumoxide::crypto::box_::curve25519xsalsa20poly1305 as crypto_box;
use sodiumoxide::crypto::sealedbox::seal;
use sodiumoxide::crypto::sign::ed25519;
use std::any::Any;

#[derive(Debug, Clone)]
pub struct Encrypter {
    base: BaseMatter,
}

impl Encrypter {
    pub fn new(
        raw: Option<&[u8]>,
        code: Option<&str>,
        verkey: Option<&[u8]>,
    ) -> Result<Self, MatterError> {
        let code = code.unwrap_or(mtr_dex::X25519);

        // Handle verkey conversion if raw is not provided
        let raw_bytes = if raw.is_none() && verkey.is_some() {
            let verfer = Verfer::from_qb64b(&mut verkey.unwrap().to_vec(), None)?;

            if verfer.code() != mtr_dex::ED25519N && verfer.code() != mtr_dex::ED25519 {
                return Err(MatterError::ValueError(format!(
                    "Unsupported verkey derivation code = {}",
                    verfer.code()
                ))
                .into());
            }

            // Convert signing public key to encryption public key
            let signing_pk = ed25519::PublicKey::from_slice(verfer.raw()).ok_or_else(|| {
                MatterError::ValueError("Invalid verkey format".to_string()).into()
            })?;
            let encryption_pk = ed25519_pk_to_x25519_pk(&signing_pk)?;
            encryption_pk.as_ref().to_vec()
        } else if let Some(r) = raw {
            r.to_vec()
        } else {
            return Err(MatterError::ValueError(
                "Either raw or verkey must be provided".to_string(),
            )
            .into());
        };

        // Check supported encryption code
        if code != mtr_dex::X25519 {
            return Err(
                MatterError::ValueError(format!("Unsupported encrypter code = {}", code)).into(),
            );
        }

        let base = BaseMatter {
            code: code.to_string(),
            raw: raw_bytes,
            soft: String::new(), // Will be set by the Matter implementation
        };

        Ok(Self { base })
    }

    pub fn from_qb64(qb64: &str) -> Result<Self, MatterError> {
        let mut qb64b = qb64.as_bytes().to_vec();
        Self::from_qb64b(&mut qb64b, Some(true))
    }

    pub fn verify_seed(&self, seed: &[u8]) -> Result<bool, MatterError> {
        // Verify that private signing key seed corresponds to public encryption key
        let signer = Signer::from_qb64b(&mut seed.to_vec(), None)?;

        // Generate keypair from seed
        let seed_raw = signer.raw();
        let seed_bytes = ed25519::Seed::from_slice(seed_raw)
            .ok_or_else(|| MatterError::ValueError("Invalid seed format".to_string()).into())?;
        let (verkey, _sigkey) = ed25519::keypair_from_seed(&seed_bytes);

        // Convert signing public key to encryption public key
        let encryption_pk = ed25519_pk_to_x25519_pk(&verkey)?;

        Ok(encryption_pk.as_ref() == self.raw())
    }

    pub fn encrypt(
        &self,
        ser: Option<&[u8]>,
        prim: Option<&dyn Matter>,
        code: Option<&str>,
    ) -> Result<Cipher, MatterError> {
        // Get serialization from either ser or prim
        let mut code = code;
        let serialization = if let Some(s) = ser {
            s.to_vec()
        } else if let Some(p) = prim {
            if code.is_none() {
                // Determine default code based on primitive type
                if p.code() == mtr_dex::SALT_128 {
                    // Use p.qb64b() for qb64 serialization
                    code = Some(mtr_dex::X25519_CIPHER_SALT);
                    p.qb64b()
                } else if p.code() == mtr_dex::ED25519_SEED {
                    code = Some(mtr_dex::X25519_CIPHER_SEED);
                    p.qb64b()
                    // Use p.qb64b() for qb64 serialization
                } else {
                    return Err(MatterError::ValueError(format!(
                        "Unsupported primitive with code = {} when cipher code is missing",
                        p.code()
                    ))
                    .into());
                }
            } else {
                // Use appropriate serialization based on code
                if self.is_qb64_cipher_code(code.unwrap()) {
                    p.qb64b()
                } else if self.is_qb2_cipher_code(code.unwrap()) {
                    p.qb2()
                } else if self.is_stream_cipher_code(code.unwrap()) {
                    // For demonstration, we'll use qb2 here
                    p.qb2()
                } else {
                    return Err(MatterError::InvalidCode(format!(
                        "Invalid primitive cipher code = {} not qb64 or qb2",
                        code.unwrap()
                    ))
                    .into());
                }
            }
        } else {
            return Err(MatterError::EmptyMaterialError(
                "Neither serialization or primitive are provided".to_string(),
            )
            .into());
        };

        // Default code if none provided
        let cipher_code = code.unwrap_or(mtr_dex::X25519_CIPHER_L0);

        self.encrypt_x25519(&serialization, cipher_code)
    }

    fn encrypt_x25519(&self, ser: &[u8], code: &str) -> Result<Cipher, MatterError> {
        // Create PublicKey from raw bytes
        let public_key = crypto_box::PublicKey::from_slice(self.raw()).ok_or_else(|| {
            MatterError::ValueError("Invalid public key format".to_string()).into()
        })?;

        // Encrypt data using sealed box
        let cipher_raw = seal(ser, &public_key);

        // Create Cipher with encrypted data
        Cipher::new(Some(&cipher_raw), Some(code))
    }

    // Helper methods to check cipher code types
    fn is_qb64_cipher_code(&self, code: &str) -> bool {
        cix_all_qb64_dex::TUPLE.contains(&code)
    }

    fn is_qb2_cipher_code(&self, code: &str) -> bool {
        cix_var_qb2_dex::TUPLE.contains(&code)
    }

    fn is_stream_cipher_code(&self, code: &str) -> bool {
        // Check if code is in CiXVarStrmDex
        cix_var_strm_dex::TUPLE.contains(&code)
    }
}

impl Parsable for Encrypter {
    fn from_qb64b(data: &mut Vec<u8>, strip: Option<bool>) -> Result<Self, MatterError> {
        let base = BaseMatter::from_qb64b(data, strip)?;
        if base.code() != mtr_dex::X25519_PRIVATE {
            return Err(MatterError::InvalidCode(format!(
                "Unsupported decrypter code = {}",
                base.code()
            )));
        }

        Ok(Encrypter { base })
    }

    fn from_qb2(data: &mut Vec<u8>, strip: Option<bool>) -> Result<Self, MatterError> {
        let base = BaseMatter::from_qb2(data, strip)?;
        if base.code() != mtr_dex::X25519_PRIVATE {
            return Err(MatterError::InvalidCode(format!(
                "Unsupported decrypter code = {}",
                base.code()
            )));
        }

        Ok(Encrypter { base })
    }
}

impl Matter for Encrypter {
    fn code(&self) -> &str {
        &self.base.code
    }

    fn raw(&self) -> &[u8] {
        &self.base.raw
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
        &self.base.soft
    }

    fn full_size(&self) -> usize {
        self.base.full_size()
    }

    fn size(&self) -> usize {
        self.base.size()
    }

    fn is_transferable(&self) -> bool {
        false
    }

    fn is_digestive(&self) -> bool {
        false
    }

    fn is_prefixive(&self) -> bool {
        false
    }

    fn is_special(&self) -> bool {
        false
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cesr::prefixer::Prefixer;
    use crate::cesr::signing::ed25519_sk_to_x25519_sk;
    use sodiumoxide::crypto::box_::curve25519xsalsa20poly1305 as crypto_box;
    use sodiumoxide::crypto::sealedbox::open;
    use sodiumoxide::crypto::sign::ed25519;

    #[test]
    fn test_encrypter() {
        // Initialize sodium for tests
        sodiumoxide::init().unwrap();

        // Verify that the seed bytes sizes are the same between crypto_box and crypto_sign
        assert_eq!(
            ed25519::SEEDBYTES,
            crypto_box::SEEDBYTES,
            "Seed byte lengths must match"
        );
        assert_eq!(ed25519::SEEDBYTES, 32, "Seed byte length should be 32");

        // Define test seed and salt
        let seed = &[
            0x18, 0x3b, 0x30, 0xc4, 0x0f, 0x2a, 0x76, 0x46, 0xfa, 0xe3, 0xa2, 0x45, 0x65, 0x65,
            0x1f, 0x96, 0x6f, 0xce, 0x29, 0x47, 0x85, 0xe3, 0x58, 0x86, 0xda, 0x04, 0xf0, 0xdc,
            0xde, 0x06, 0xc0, 0x2b,
        ];

        // Create seed matter and verify its qb64b representation
        let seed_matter =
            BaseMatter::new(Some(seed), Some(mtr_dex::ED25519_SEED), None, None).unwrap();
        let seed_qb64b = seed_matter.qb64b();
        assert_eq!(
            seed_qb64b, b"ABg7MMQPKnZG-uOiRWVlH5ZvzilHheNYhtoE8NzeBsAr",
            "Seed qb64b encoding is incorrect"
        );

        // Create and verify salt matter
        let salt = &[
            0x36, 0x08, 0x64, 0x0d, 0xa1, 0xbb, 0x39, 0x8d, 0x70, 0x8d, 0xa0, 0xc0, 0x13, 0x4a,
            0x87, 0x72,
        ];
        let salt_matter = BaseMatter::new(Some(salt), Some(mtr_dex::SALT_128), None, None).unwrap();
        let salt_qb64b = salt_matter.qb64b();
        assert_eq!(
            salt_qb64b, b"0AA2CGQNobs5jXCNoMATSody",
            "Salt qb64b encoding is incorrect"
        );

        // Create seed for crypto operations
        let crypt_seed = &[
            0x68, 0x2c, 0x23, 0x7c, 0x8a, 0x70, 0x22, 0x12, 0xc4, 0x33, 0x74, 0x32, 0xa6, 0xe1,
            0x18, 0x19, 0xf0, 0x66, 0x32, 0x2c, 0x79, 0xc4, 0xc2, 0x31, 0x40, 0xf5, 0x40, 0x15,
            0x2e, 0xa2, 0x1a, 0xcf,
        ];

        // Create a signer with the crypto seed
        let crypt_signer =
            Signer::new(Some(crypt_seed), Some(mtr_dex::ED25519_SEED), Some(true)).unwrap();

        // Generate key pairs from seed
        let seed_bytes = ed25519::Seed::from_slice(crypt_seed).unwrap();
        let (verkey, sigkey) = ed25519::keypair_from_seed(&seed_bytes);

        // Convert signing keys to encryption keys
        let pubkey = ed25519_pk_to_x25519_pk(&verkey).unwrap();
        let prikey = ed25519_sk_to_x25519_sk(&sigkey).unwrap();

        // Test empty constructor
        let result = Encrypter::new(None, None, None);
        assert!(result.is_err(), "Encrypter should fail with no parameters");

        // Test constructor with raw pubkey
        let encrypter = Encrypter::new(Some(&pubkey.as_ref()), None, None).unwrap();
        assert_eq!(
            encrypter.code(),
            mtr_dex::X25519,
            "Default code should be X25519"
        );
        assert_eq!(
            encrypter.qb64(),
            "CAF7Wr3XNq5hArcOuBJzaY6Nd23jgtUVI6KDfb3VngkR",
            "Encrypter qb64 is incorrect"
        );
        assert_eq!(
            encrypter.raw(),
            &pubkey.0,
            "Encrypter raw should match pubkey"
        );

        // Test seed verification
        let verify_result = encrypter.verify_seed(&crypt_signer.qb64b()).unwrap();
        assert!(verify_result, "Seed verification should succeed");

        // Test verkey constructor using qb64 string
        let verfer = Verfer::new(Some(&verkey.0), Some(mtr_dex::ED25519)).unwrap();
        let encrypter_from_verkey = Encrypter::new(None, None, Some(&verfer.qb64b())).unwrap();
        assert_eq!(
            encrypter_from_verkey.code(),
            mtr_dex::X25519,
            "Code should be X25519"
        );
        assert_eq!(
            encrypter_from_verkey.qb64(),
            "CAF7Wr3XNq5hArcOuBJzaY6Nd23jgtUVI6KDfb3VngkR",
            "Encrypter qb64 from verkey is incorrect"
        );
        assert_eq!(
            encrypter_from_verkey.raw(),
            &pubkey.0,
            "Encrypter raw should match pubkey"
        );

        // Test verkey constructor using bytes
        let encrypter_from_verkey_bytes =
            Encrypter::new(None, None, Some(verfer.qb64b().as_slice())).unwrap();
        assert_eq!(
            encrypter_from_verkey_bytes.code(),
            mtr_dex::X25519,
            "Code should be X25519"
        );
        assert_eq!(
            encrypter_from_verkey_bytes.qb64(),
            "CAF7Wr3XNq5hArcOuBJzaY6Nd23jgtUVI6KDfb3VngkR",
            "Encrypter qb64 from verkey bytes is incorrect"
        );
        assert_eq!(
            encrypter_from_verkey_bytes.raw(),
            &pubkey.0,
            "Encrypter raw should match pubkey"
        );

        // Test with Prefixer
        let prefixer = Prefixer::from_qb64b(&mut verfer.qb64b(), None).unwrap();
        let encrypter_from_prefixer =
            Encrypter::new(None, None, Some(prefixer.qb64b().as_slice())).unwrap();
        assert_eq!(
            encrypter_from_prefixer.code(),
            mtr_dex::X25519,
            "Code should be X25519"
        );
        assert_eq!(
            encrypter_from_prefixer.qb64(),
            "CAF7Wr3XNq5hArcOuBJzaY6Nd23jgtUVI6KDfb3VngkR",
            "Encrypter qb64 from prefixer is incorrect"
        );
        assert_eq!(
            encrypter_from_prefixer.raw(),
            &pubkey.0,
            "Encrypter raw should match pubkey"
        );

        // Test encrypt method with seed
        let encrypter = Encrypter::new(Some(&pubkey.0), None, None).unwrap();
        assert_eq!(encrypter.code(), mtr_dex::X25519, "Code should be X25519");
        assert_eq!(
            encrypter.qb64(),
            "CAF7Wr3XNq5hArcOuBJzaY6Nd23jgtUVI6KDfb3VngkR",
            "Encrypter qb64 is incorrect"
        );
        assert_eq!(
            encrypter.raw(),
            &pubkey.0,
            "Encrypter raw should match pubkey"
        );

        let verify_result = encrypter.verify_seed(&crypt_signer.qb64b()).unwrap();
        assert!(verify_result, "Seed verification should succeed");

        // Encrypt seed qb64b
        let cipher = encrypter
            .encrypt(Some(&seed_qb64b), None, Some(mtr_dex::X25519_CIPHER_SEED))
            .unwrap();
        assert_eq!(
            cipher.code(),
            mtr_dex::X25519_CIPHER_SEED,
            "Cipher code should be X25519_CIPHER_SEED"
        );

        // Decrypt and verify the encrypted seed
        let uncb = open(&cipher.raw(), &crypto_box::PublicKey(pubkey.0), &prikey).unwrap();
        assert_eq!(uncb, seed_qb64b, "Decrypted seed should match original");

        // Encrypt salt qb64b
        let cipher = encrypter
            .encrypt(Some(&salt_qb64b), None, Some(mtr_dex::X25519_CIPHER_SALT))
            .unwrap();
        assert_eq!(
            cipher.code(),
            mtr_dex::X25519_CIPHER_SALT,
            "Cipher code should be X25519_CIPHER_SALT"
        );

        // Decrypt and verify the encrypted salt
        let uncb = open(&cipher.raw(), &crypto_box::PublicKey(pubkey.0), &prikey).unwrap();
        assert_eq!(uncb, salt_qb64b, "Decrypted salt should match original");
    }
}
