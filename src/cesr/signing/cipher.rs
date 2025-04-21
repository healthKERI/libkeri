use std::any::Any;
use crate::cesr::{mtr_dex, raw_size, BaseMatter, Parsable};
use crate::cesr::signing::decrypter::Decrypter;
use crate::errors::MatterError;
use crate::Matter;

#[derive(Debug, Clone)]
pub struct Cipher {
    base: BaseMatter,
}

impl Cipher {
    /// Creates a new Cipher instance
    ///
    /// # Arguments
    ///
    /// * `raw` - Optional raw binary encrypted cipher text
    /// * `code` - Optional CESR code indicating the type of plain text that has been encrypted
    ///
    /// # Returns
    ///
    /// * `Result<Self, MatterError>` - New Cipher instance or error
    pub fn new(raw: Option<&[u8]>, code: Option<&str>) -> Result<Self, MatterError> {
        // If raw is provided but code is not, determine code based on raw size
        let code = match (raw, code) {
            (Some(r), None) => {
                if r.len() == raw_size(mtr_dex::X25519_CIPHER_SALT)? { // X25519_Cipher_Salt size
                    mtr_dex::X25519_CIPHER_SALT
                } else if r.len() == raw_size(mtr_dex::X25519_CIPHER_SEED)? { // X25519_Cipher_Seed size
                    mtr_dex::X25519_CIPHER_SEED
                } else {
                    return Err(MatterError::ValueError(format!(
                        "Unsupported fixed raw size {} for cipher.",
                        r.len()
                    )));
                }
            },
            (_, Some(c)) => c,
            _ => return Err(MatterError::EmptyMaterial("Both raw and code cannot be None for Cipher".to_string())),
        };

        // Validate that the code is a supported cipher code
        if !Self::is_supported_code(code) {
            return Err(MatterError::UnexpectedCode(format!("Unsupported cipher code = {}", code)));
        }

        let base = BaseMatter::new(raw, Some(code), None, None)?;
        Ok(Self { base })
    }

    /// Creates a Cipher from raw binary data with automatically determined code
    ///
    /// # Arguments
    ///
    /// * `raw` - Raw binary encrypted cipher text
    ///
    /// # Returns
    ///
    /// * `Result<Self, MatterError>` - New Cipher instance or error
    pub fn from_raw(raw: &[u8]) -> Result<Self, MatterError> {
        Self::new(Some(raw), None)
    }

    /// Creates a Cipher from qb64 encoded string
    ///
    /// # Arguments
    ///
    /// * `qb64` - qb64 encoded string
    ///
    /// # Returns
    ///
    /// * `Result<Self, MatterError>` - New Cipher instance or error
    pub fn from_qb64(qb64: &str) -> Result<Self, MatterError> {
        let base = BaseMatter::from_qb64(qb64)?;

        if !Self::is_supported_code(base.code()) {
            return Err(MatterError::UnexpectedCode(format!("Unsupported cipher code = {}", base.code())));
        }

        Ok(Self { base })
    }

    /// Decrypts the cipher text using the provided private key or seed
    ///
    /// # Arguments
    ///
    /// * `prikey` - Optional qb64 or qb64b serialization of private decryption key
    /// * `seed` - Optional qb64 or qb64b serialization of private signing key seed
    /// * `transferable` - Whether the returned signer (if applicable) should be transferable
    /// * `bare` - If true, returns plaintext itself; if false, returns an instance holding plaintext
    ///
    /// # Returns
    ///
    /// * `Result<Box<dyn Any>, MatterError>` - Decrypted result or error
    pub fn decrypt(
        &self,
        prikey: Option<&[u8]>,
        seed: Option<&[u8]>,
        transferable: Option<bool>,
        bare: Option<bool>,
    ) -> Result<Box<dyn Any>, MatterError> {
        let decrypter = if prikey.is_some() {
            Decrypter::from_qb64b(&mut prikey.unwrap().to_vec(), Some(false))?
        } else {
            Decrypter::new(None, None, seed)?
        };

        decrypter.decrypt(Some(self), None, None, transferable, bare)
    }

    /// Checks if the given code is supported by Cipher
    ///
    /// # Arguments
    ///
    /// * `code` - CESR code to check
    ///
    /// # Returns
    ///
    /// * `bool` - True if code is supported, false otherwise
    fn is_supported_code(code: &str) -> bool {
        // Check if code is in CiXDex
        matches!(code, mtr_dex::X25519_CIPHER_SEED | mtr_dex::X25519_CIPHER_SALT) // X25519_Cipher_Seed, X25519_Cipher_Salt
    }
}

impl Parsable for Cipher {
    fn from_qb64b(data: &mut Vec<u8>, strip: Option<bool>) -> Result<Self, MatterError> {
        let base = BaseMatter::from_qb64b(data, strip)?;

        if !Self::is_supported_code(base.code()) {
            return Err(MatterError::UnexpectedCode(format!("Unsupported cipher code = {}", base.code())));
        }

        Ok(Self { base })
    }

    fn from_qb2(data: &mut Vec<u8>, strip: Option<bool>) -> Result<Self, MatterError> {
        let base = BaseMatter::from_qb2(data, strip)?;

        if !Self::is_supported_code(base.code()) {
            return Err(MatterError::UnexpectedCode(format!("Unsupported cipher code = {}", base.code())));
        }

        Ok(Self { base })
    }
}

impl Matter for Cipher {
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
    use sodiumoxide::crypto::sign::{ed25519, SEEDBYTES as SIGN_SEEDBYTES};
    use sodiumoxide::crypto::box_::{SEEDBYTES as BOX_SEEDBYTES};
    use sodiumoxide::crypto::sealedbox::{open, seal};
    use crate::cesr::signing::{ed25519_pk_to_x25519_pk, ed25519_sk_to_x25519_sk, Salter, Signer};

    #[test]
    fn test_cipher() -> Result<(), MatterError>{
        // Initialize sodium
        sodiumoxide::init().expect("Sodium initialization failed");

        // Verify that box and sign seed lengths are both 32 bytes
        assert_eq!(BOX_SEEDBYTES, SIGN_SEEDBYTES);
        assert_eq!(BOX_SEEDBYTES, 32);

        // Use predefined seed instead of random for reproducible tests
        let seed = [
            0x18, 0x3b, 0x30, 0xc4, 0x0f, 0x2a, 0x76, 0x46, 0xfa, 0xe3, 0xa2, 0x45, 0x65, 0x65,
            0x1f, 0x96, 0x6f, 0xce, 0x29, 0x47, 0x85, 0xe3, 0x58, 0x86, 0xda, 0x04, 0xf0, 0xdc,
            0xde, 0x06, 0xc0, 0x2b
        ];

        // Create Matter instance for the seed and get qb64b
        let seed_matter = BaseMatter::new(Some(&seed), Some(mtr_dex::ED25519_SEED), None, None)
            .expect("Failed to create seed matter");
        let seed_qb64b = seed_matter.qb64b();
        assert_eq!(std::str::from_utf8(&seed_qb64b).unwrap(),
                   "ABg7MMQPKnZG-uOiRWVlH5ZvzilHheNYhtoE8NzeBsAr");

        // Define salt
        let salt = [
            0x36, 0x08, 0x64, 0x0d, 0xa1, 0xbb, 0x39, 0x8d, 0x70, 0x8d, 0xa0, 0xc0, 0x13, 0x4a,
            0x87, 0x72
        ];

        // Create Matter instance for the salt and get qb64b
        let salt_matter = BaseMatter::new(Some(&salt), Some(mtr_dex::SALT_128), None, None)
            .expect("Failed to create salt matter");
        let salt_qb64b = salt_matter.qb64b();
        assert_eq!(std::str::from_utf8(&salt_qb64b).unwrap(),
                   "0AA2CGQNobs5jXCNoMATSody");

        // Define cryptographic seed for key generation
        let crypt_seed = [
            0x68, 0x2c, 0x23, 0x7c, 0x8a, 0x70, 0x22, 0x12, 0xc4, 0x33, 0x74, 0x32, 0xa6, 0xe1,
            0x18, 0x19, 0xf0, 0x66, 0x32, 0x2c, 0x79, 0xc4, 0xc2, 0x31, 0x40, 0xf5, 0x40, 0x15,
            0x2e, 0xa2, 0x1a, 0xcf
        ];

        let seed = ed25519::Seed::from_slice(&crypt_seed)
            .ok_or_else(|| MatterError::CryptoError("Invalid Ed25519 seed".to_string()))?;
        let (ed_pk, ed_sk) = ed25519::keypair_from_seed(&seed);

        let pub_key = ed25519_pk_to_x25519_pk(&ed_pk)?;
        let pri_key = ed25519_sk_to_x25519_sk(&ed_sk)?;

        // Test empty material error
        let empty_result = Cipher::new(None, None);
        assert!(empty_result.is_err());
        let err = empty_result.unwrap_err();
        match err {
            MatterError::EmptyMaterial(_) => {},
            _ => panic!("Expected EmptyMaterial error, got: {:?}", err),
        }

        // Encrypt seed with box_seal
        let raw = seal(&seed_qb64b, &pub_key);

        // Test Cipher creation with raw data only
        let cipher = Cipher::new(Some(&raw), None).expect("Failed to create cipher");
        assert_eq!(cipher.code(), mtr_dex::X25519_CIPHER_SEED); // X25519_Cipher_Seed

        // Decrypt and verify
        let uncb = open(&raw, &pub_key, &pri_key).expect("Failed to decrypt");
        assert_eq!(uncb, seed_qb64b);

        // Test Cipher creation with explicit code
        let cipher = Cipher::new(Some(&raw), Some(mtr_dex::X25519_CIPHER_SEED)).expect("Failed to create cipher");
        assert_eq!(cipher.code(), mtr_dex::X25519_CIPHER_SEED); // X25519_Cipher_Seed

        let uncb = open(&cipher.raw(), &pub_key, &pri_key).expect("Failed to decrypt");
        assert_eq!(uncb, seed_qb64b);

        // Test .decrypt method
        let pri_key_matter = BaseMatter::new(Some(pri_key.as_ref()), Some(mtr_dex::X25519_PRIVATE), None, None)
            .expect("Failed to create private key matter");
        let pri_key_qb64b = pri_key_matter.qb64b();

        // Test decryption with private key
        let decrypted = cipher.decrypt(Some(&pri_key_qb64b), None, None, Some(false))
            .expect("Failed to decrypt with prikey");
        let decrypted_matter = decrypted.downcast_ref::<Signer>()
            .expect("Failed to downcast to Matter");
        assert_eq!(decrypted_matter.qb64b(), seed_qb64b);

        // Test bare decryption with private key
        let decrypted_bare = cipher.decrypt(Some(&pri_key_qb64b), None, None, Some(true))
            .expect("Failed to decrypt with prikey (bare)");
        let bare_bytes = decrypted_bare.downcast_ref::<Vec<u8>>()
            .expect("Failed to downcast to Vec<u8>");
        assert_eq!(bare_bytes, &seed_qb64b);

        // Test decryption with seed
        let crypt_seed_matter = BaseMatter::new(Some(&crypt_seed), Some(mtr_dex::ED25519_SEED), None, None)
            .expect("Failed to create crypt seed matter");
        let crypt_seed_qb64b = crypt_seed_matter.qb64b();

        let decrypted_from_seed = cipher.decrypt(None, Some(&crypt_seed_qb64b), None, Some(false))
            .expect("Failed to decrypt with seed");
        let decrypted_seed_matter = decrypted_from_seed.downcast_ref::<Signer>()
            .expect("Failed to downcast to Matter");
        assert_eq!(decrypted_seed_matter.qb64b(), seed_qb64b);

        // Test bare decryption with seed
        let decrypted_seed_bare = cipher.decrypt(None, Some(&crypt_seed_qb64b), None, Some(true))
            .expect("Failed to decrypt with seed (bare)");
        let seed_bare_bytes = decrypted_seed_bare.downcast_ref::<Vec<u8>>()
            .expect("Failed to downcast to Vec<u8>");
        assert_eq!(seed_bare_bytes, &seed_qb64b);

        // Test wrong but shorter code
        let wrong_code_cipher = Cipher::new(Some(&raw), Some(mtr_dex::X25519_CIPHER_SALT)).expect("Failed to create cipher with wrong code");
        assert_eq!(wrong_code_cipher.code(), mtr_dex::X25519_CIPHER_SALT); // X25519_Cipher_Salt

        // Decryption should fail with ValueError
        let decrypt_result = open(&wrong_code_cipher.raw(), &pub_key, &pri_key);
        assert!(decrypt_result.is_err());

        // Encrypt salt with box_seal
        let salt_raw = seal(&salt_qb64b, &pub_key);
        // Test Cipher creation with salt raw data only
        let salt_cipher = Cipher::new(Some(&salt_raw), None).expect("Failed to create salt cipher");
        assert_eq!(salt_cipher.code(), mtr_dex::X25519_CIPHER_SALT); // X25519_Cipher_Salt

        // Decrypt and verify
        let salt_uncb = open(&salt_raw, &pub_key, &pri_key).expect("Failed to decrypt salt");
        assert_eq!(salt_uncb, salt_qb64b);

        // Test Cipher creation with explicit code
        let salt_cipher = Cipher::new(Some(&salt_raw), Some(mtr_dex::X25519_CIPHER_SALT)).expect("Failed to create salt cipher with code");
        assert_eq!(salt_cipher.code(), mtr_dex::X25519_CIPHER_SALT); // X25519_Cipher_Salt

        let salt_uncb = open(&salt_cipher.raw(), &pub_key, &pri_key).expect("Failed to decrypt salt");
        assert_eq!(salt_uncb, salt_qb64b);

        // Test wrong code (too big for raw bytes)
        let wrong_size_result = Cipher::new(Some(&salt_raw), Some(mtr_dex::X25519_CIPHER_SEED));
        assert!(wrong_size_result.is_err());
        match wrong_size_result.unwrap_err() {
            MatterError::RawMaterial(_) => {},
            err => panic!("Expected RawMaterial error, got: {:?}", err),
        }

        // Test .decrypt method for salt
        let decrypted_salt = salt_cipher.decrypt(Some(&pri_key_qb64b), None, None, Some(false))
            .expect("Failed to decrypt salt with prikey");
        let decrypted_salt_matter = decrypted_salt.downcast_ref::<Salter>()
            .expect("Failed to downcast to Matter");
        assert_eq!(decrypted_salt_matter.qb64b(), salt_qb64b);

        // Test bare decryption for salt
        let decrypted_salt_bare = salt_cipher.decrypt(Some(&pri_key_qb64b), None, None, Some(true))
            .expect("Failed to decrypt salt with prikey (bare)");
        let salt_bare_bytes = decrypted_salt_bare.downcast_ref::<Vec<u8>>()
            .expect("Failed to downcast to Vec<u8>");
        assert_eq!(salt_bare_bytes, &salt_qb64b);

        // Test salt decryption with seed
        let decrypted_salt_from_seed = salt_cipher.decrypt(None, Some(&crypt_seed_qb64b), None, Some(false))
            .expect("Failed to decrypt salt with seed");
        let decrypted_salt_seed_matter = decrypted_salt_from_seed.downcast_ref::<Salter>()
            .expect("Failed to downcast to Matter");
        assert_eq!(decrypted_salt_seed_matter.qb64b(), salt_qb64b);

        // Test bare salt decryption with seed
        let decrypted_salt_seed_bare = salt_cipher.decrypt(None, Some(&crypt_seed_qb64b), None, Some(true))
            .expect("Failed to decrypt salt with seed (bare)");
        let salt_seed_bare_bytes = decrypted_salt_seed_bare.downcast_ref::<Vec<u8>>()
            .expect("Failed to downcast to Vec<u8>");
        assert_eq!(salt_seed_bare_bytes, &salt_qb64b);

        // Test invalid code
        let invalid_code_result = Cipher::new(Some(&raw), Some("BEAD"));
        assert!(invalid_code_result.is_err());
        match invalid_code_result.unwrap_err() {
            MatterError::UnexpectedCode(_) => {},
            err => panic!("Expected UnexpectedCode error, got: {:?}", err),
        }

        // Test bad raw size
        let too_small_raw = &raw[0..raw.len()-1];
        let too_small_result = Cipher::new(Some(too_small_raw), None);
        assert!(too_small_result.is_err());
        match too_small_result.unwrap_err() {
            MatterError::ValueError(_) => {},
            err => panic!("Expected InvalidSize error, got: {:?}", err),
        }

        // Test raw too big
        let mut too_big_raw = raw.clone();
        too_big_raw.push(b'_');
        let too_big_result = Cipher::new(Some(&too_big_raw), None);
        assert!(too_big_result.is_err());
        match too_big_result.unwrap_err() {
            MatterError::ValueError(_) => {},
            err => panic!("Expected InvalidSize error, got: {:?}", err),
        }

        // Test bad salt raw size
        let too_small_salt_raw = &salt_raw[0..salt_raw.len()-1];
        let too_small_salt_result = Cipher::new(Some(too_small_salt_raw), None);
        assert!(too_small_salt_result.is_err());
        match too_small_salt_result.unwrap_err() {
            MatterError::ValueError(_) => {},
            err => panic!("Expected InvalidSize error, got: {:?}", err),
        }

        // Test salt raw too big
        let mut too_big_salt_raw = salt_raw.clone();
        too_big_salt_raw.push(b'_');
        let too_big_salt_result = Cipher::new(Some(&too_big_salt_raw), None);
        assert!(too_big_salt_result.is_err());
        match too_big_salt_result.unwrap_err() {
            MatterError::ValueError(_) => {},
            err => panic!("Expected InvalidSize error, got: {:?}", err),
        }

        Ok(())
    }
}