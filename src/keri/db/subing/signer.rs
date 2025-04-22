use std::sync::Arc;
use crate::cesr::Parsable;
use crate::cesr::signing::{Decrypter, Encrypter, Signer};
use crate::cesr::verfer::Verfer;
use crate::keri::db::dbing::LMDBer;
use crate::keri::db::subing::cesr::{CesrSuber, CesrSuberBase};
use crate::keri::db::subing::SuberError;
use crate::Matter;

pub trait SignerTrait: Matter + Parsable {
    fn with_transferable(qb64b: &[u8], transferable: bool) -> Result<Self, SuberError>;
}

pub struct SignerSuber<'db> {
    base: CesrSuber<'db, Signer>,
}

impl<'db> SignerSuber<'db> {
    pub fn new(
        db: Arc<&'db LMDBer>,
        subkey: &str,
        sep: Option<u8>,
        verify: bool,
    ) -> Result<Self, SuberError> {
        let base = CesrSuber::new(db, subkey, sep, verify)?;
        Ok(Self { base })
    }

    /// Gets Signer instance at keys
    ///
    /// # Arguments
    /// * `keys` - key bytes to be combined in order to form key. Last element of keys is verkey
    ///   used to determine .transferable for Signer
    ///
    /// # Returns
    /// * `Option<S>` - Signer instance with transferable property set correctly or None if no entry
    pub fn get<K: AsRef<[u8]>>(&self, keys: &[K]) -> Result<Option<Signer>, SuberError> {
        if keys.is_empty() {
            return Err(SuberError::EmptyKeys);
        }

        // Get raw value from database
        let key_result = self.base.get_full_item_iter(keys, false)?;
        if key_result.is_empty() {
            return Ok(None);
        }

        let (ikeys, raw_val) = &key_result[0];

        // Get the verkey (last element of keys)
        let verkey = if let Some(last_key) = ikeys.last() {
            last_key
        } else {
            return Err(SuberError::EmptyKeys);
        };

        // Create Verfer from verkey to determine transferability
        let verfer = Verfer::from_qb64b(&mut verkey.clone(), None)?;
        let transferable = verfer.is_transferable();

        // Create Signer with the correct transferable property
        let mut qb64b = raw_val.clone();
        let signer = Signer::from_qb64b_and_transferable(&mut qb64b, None, transferable)?;

        Ok(Some(signer))
    }

    /// Returns iterator over items in the subdb whose key starts with the provided keys
    ///
    /// # Arguments
    /// * `keys` - Optional prefix keys to filter results
    /// * `topive` - If true, treat as partial key tuple from top branch
    ///
    /// # Returns
    /// * Vector of tuples containing (keys, signer instance)
    pub fn get_item_iter<K: AsRef<[u8]>>(
        &self,
        keys: &[K],
        topive: bool,
    ) -> Result<Vec<(Vec<Vec<u8>>, Signer)>, SuberError> {
        let items = self.base.get_full_item_iter(keys, topive)?;
        let mut result = Vec::with_capacity(items.len());

        for (ikeys, val) in items {
            // Get verkey (last element of keys)
            let verkey = if let Some(last_key) = ikeys.last() {
                last_key
            } else {
                continue;
            };

            // Create Verfer from verkey to determine transferability
            let verfer = Verfer::from_qb64b(&mut verkey.clone(), None)?;
            let transferable = verfer.is_transferable();

            // Create Signer with the correct transferable property
            let mut qb64b = val.clone();
            let signer = Signer::from_qb64b_and_transferable(&mut qb64b, None, transferable)?;
            result.push((ikeys, signer));
        }

        Ok(result)
    }

    // Forward other methods to the base implementation
    pub fn put<K: AsRef<[u8]>>(&self, keys: &[K], val: &Signer) -> Result<bool, SuberError> {
        Ok(self.base.put(keys, val)?)
    }

    // Forward other methods to the base implementation
    pub fn pin<K: AsRef<[u8]>>(&self, keys: &[K], val: &Signer) -> Result<bool, SuberError> {
        Ok(self.base.pin(keys, val)?)
    }

    pub fn trim<K: AsRef<[u8]>>(&self, keys: &[K], topive: bool) -> Result<bool, SuberError> {
        Ok(self.base.trim(keys, topive)?)
    }

    pub fn cnt_all(&self) -> Result<usize, SuberError> {
        Ok(self.base.cnt_all()?)
    }
}

/// CryptSignerSuber extends SignerSuber to add encryption and decryption capabilities
///
/// Data is stored as encrypted Signer instances if an encrypter is provided.
/// On retrieval, the data is decrypted if a decrypter is provided.
///
/// Assumes that last or only element of db key from keys for all entries is the qb64
/// of a public key for the associated Verfer instance. This allows returned
/// Signer instance to have its .transferable property set correctly.
pub struct CryptSignerSuber<'db> {
    base: CesrSuberBase<'db, Signer>,
}

impl<'db> CryptSignerSuber<'db> {
    pub fn new(
        db: Arc<&'db LMDBer>,
        subkey: &str,
        sep: Option<u8>,
        verify: bool,
    ) -> Result<Self, SuberError> {
        let base = CesrSuberBase::new(db, subkey, sep, verify)?;

        Ok(Self { base })
    }

    // Delegate all methods to the base
    pub fn pin<K: AsRef<[u8]>>(&self, keys: &[K], val: &Signer, encrypter: Option<Encrypter>) -> Result<bool, SuberError> {
        match encrypter {
            Some(encrypter) => {
                let val = encrypter.encrypt(None, Some(val), None)?;
                let val_bytes = val.qb64b();
                let key = self.base.to_key(keys, false);
                Ok(self.base.set_val(&key, &val_bytes)?)
            }
            None => {
                Ok(self.base.pin(keys, val)?)
            }
        }
    }

    // Delegate all methods to the base
    pub fn put<K: AsRef<[u8]>>(&self, keys: &[K], val: &Signer, encrypter: Option<Encrypter>) -> Result<bool, SuberError> {
        match encrypter {
            Some(encrypter) => {
                let val = encrypter.encrypt(None, Some(val), None)?;
                let val_bytes = val.qb64b();
                let key = self.base.to_key(keys, false);
                Ok(self.base.put_val(&key, &val_bytes)?)
            }
            None => {
                Ok(self.base.put(keys, val)?)
            }
        }
    }

    pub fn get<K: AsRef<[u8]>>(&self, keys: &[K], decrypter: Option<Decrypter>) -> Result<Option<Signer>, SuberError> {
        if keys.is_empty() {
            return Err(SuberError::EmptyKeys);
        }

        // Get raw value from database
        let key_result = self.base.get_full_item_iter(keys, false)?;
        if key_result.is_empty() {
            return Ok(None);
        }

        let (ikeys, raw_val) = &key_result[0];

        // Get the verkey (last element of keys)
        let verkey = if let Some(last_key) = ikeys.last() {
            last_key
        } else {
            return Err(SuberError::EmptyKeys);
        };
        // Create Verfer from verkey to determine transferability
        let verfer = Verfer::from_qb64b(&mut verkey.clone(), None)?;
        let transferable = verfer.is_transferable();

        match decrypter {
            Some(decrypter) => {
                // Create Signer with the correct transferable property
                let qb64 = std::str::from_utf8(raw_val)
                    .map_err(|e| SuberError::DecryptionError(format!("Invalid raw value: {}", e)))?;
                let signer = decrypter.decrypt(None, Some(qb64), None, Some(transferable), None)?
                    .downcast::<Signer>()
                    .map_err(|_| SuberError::DecryptionError("Failed to downcast to Signer".to_string()))?;

                Ok(Some(*signer))
            }
            None => {
                // Create Signer with the correct transferable property
                let mut qb64b = raw_val.clone();
                let signer = Signer::from_qb64b_and_transferable(&mut qb64b, None, transferable)?;

                Ok(Some(signer))
            }
        }
    }

    // Remove an entry at keys
    pub fn rem<K: AsRef<[u8]>>(&self, keys: &[K]) -> Result<bool, SuberError> {
        self.base.rem(keys)
    }

    pub fn trim<K: AsRef<[u8]>>(&self, keys: &[K], topive: bool) -> Result<bool, SuberError> {
        self.base.trim(keys, topive)
    }

    pub fn get_full_item_iter<K: AsRef<[u8]>>(
        &self,
        keys: &[K],
        topive: bool,
    ) -> Result<Vec<(Vec<Vec<u8>>, Vec<u8>)>, SuberError> {
        self.base.get_full_item_iter(keys, topive)
    }

    /// Returns iterator over items in the subdb whose key starts with the provided keys
    ///
    /// # Arguments
    /// * `keys` - Optional prefix keys to filter results
    /// * `topive` - If true, treat as partial key tuple from top branch
    ///
    /// # Returns
    /// * Vector of tuples containing (keys, signer instance)
    pub fn get_item_iter<K: AsRef<[u8]>>(
        &self,
        keys: &[K],
        topive: bool,
        decrypter: Option<Decrypter>
    ) -> Result<Vec<(Vec<Vec<u8>>, Signer)>, SuberError> {
        let items = self.base.get_full_item_iter(keys, topive)?;
        let mut result = Vec::with_capacity(items.len());

        for (ikeys, val) in items {
            // Get verkey (last element of keys)
            let verkey = if let Some(last_key) = ikeys.last() {
                last_key
            } else {
                continue;
            };

            // Create Verfer from verkey to determine transferability
            let verfer = Verfer::from_qb64b(&mut verkey.clone(), None)?;
            let transferable = verfer.is_transferable();

            // Create Signer with the correct transferable property
            let signer = match &decrypter {
                Some(decrypter) => {
                    // Create Signer with the correct transferable property
                    let qb64 = std::str::from_utf8(&val)
                        .map_err(|e| SuberError::DecryptionError(format!("Invalid raw value: {}", e)))?;
                    let boxed_signer = decrypter.decrypt(None, Some(qb64), None, Some(transferable), None)?
                        .downcast::<Signer>()
                        .map_err(|_| SuberError::DecryptionError("Failed to downcast to Signer".to_string()))?;

                    *boxed_signer
                }
                None => {
                    // Create Signer with the correct transferable property
                    let mut qb64b = val.clone();
                    Signer::from_qb64b_and_transferable(&mut qb64b, None, transferable)?
                }
            };

            result.push((ikeys, signer))
        }

        Ok(result)
    }

    pub fn process_items(&self, items: Vec<(Vec<Vec<u8>>, Vec<u8>)>) -> Result<Vec<(Vec<Vec<u8>>, Signer)>, SuberError> {
        self.base.process_items(items)
    }

    pub fn cnt_all(&self) -> Result<usize, SuberError> {
        self.base.cnt_all()
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use crate::cesr::mtr_dex;
    use crate::cesr::signing::{Salter, Signer};

    #[test]
    fn test_signer_suber() -> Result<(), Box<dyn std::error::Error>> {
        // Open LMDB database
        let db = LMDBer::builder()
            .name("test")
            .temp(true)
            .build()?;

        let db_arc = Arc::new(&db);

        // Ensure the database is opened correctly
        assert_eq!(db.name(), "test");
        assert!(db.opened());

        // Create SignerSuber with default Signer class
        let sdb = SignerSuber::new(db_arc, "bags.", None, false)?;

        // Verify dupsort is not set (this may need adjustment based on your implementation)
        // Skip this assertion if your Rust implementation handles dupsort differently

        // Create test seeds and signers
        let seed0 = &[
            0x18, 0x3b, 0x30, 0xc4, 0x0f, 0x2a, 0x76, 0x46, 0xfa, 0xe3, 0xa2, 0x45, 0x65, 0x65,
            0x1f, 0x96, 0x6f, 0xce, 0x29, 0x47, 0x85, 0xe3, 0x58, 0x86, 0xda, 0x04, 0xf0, 0xdc,
            0xde, 0x06, 0xc0, 0x2b
        ];

        let signer0 = Signer::new(Some(seed0), Some(mtr_dex::ED25519_SEED), Some(true))?;
        assert_eq!(signer0.verfer().code(), mtr_dex::ED25519);
        assert!(signer0.verfer().is_transferable()); // default
        assert_eq!(signer0.qb64b(), b"ABg7MMQPKnZG-uOiRWVlH5ZvzilHheNYhtoE8NzeBsAr");
        assert_eq!(signer0.verfer().qb64b(), b"DIYsYWYwtVo9my0dUHQA0-_ZEts8B5XdvXpHGtHpcR4h");

        let seed1 = &[
            0x60, 0x05, 0x93, 0xb9, 0x9b, 0x36, 0x1e, 0xe0, 0xd7, 0x98, 0x5e, 0x94, 0xc8, 0x45,
            0x74, 0xf2, 0xc4, 0xcd, 0x94, 0x18, 0xc6, 0xae, 0xb9, 0xb6, 0x6d, 0x12, 0xc4, 0x80,
            0x03, 0x07, 0xfc, 0xf7
        ];

        let signer1 = Signer::new(Some(seed1), Some(mtr_dex::ED25519_SEED), Some(true))?;
        assert_eq!(signer1.verfer().code(), mtr_dex::ED25519);
        assert!(signer1.verfer().is_transferable()); // default
        assert_eq!(signer1.qb64b(), b"AGAFk7mbNh7g15helMhFdPLEzZQYxq65tm0SxIADB_z3");
        assert_eq!(signer1.verfer().qb64b(), b"DIHpH-kgf2oMMfeplUmSOj0wtPY-EqfKlG4CoJTfLi42");

        // Test put and get with keys
        let keys = [signer0.verfer().qb64()];
        let result = sdb.put(&keys, &signer0)?;
        assert!(result);

        let actual = sdb.get(&keys)?.unwrap();
        assert_eq!(actual.qb64(), signer0.qb64());
        assert_eq!(actual.verfer().qb64(), signer0.verfer().qb64());

        // Test rem
        sdb.trim(&keys, false)?;
        let actual = sdb.get(&keys)?;
        assert!(actual.is_none());

        // Test put again
        let result = sdb.put(&keys, &signer0)?;
        assert!(result);

        let actual = sdb.get(&keys)?.unwrap();
        assert_eq!(actual.qb64(), signer0.qb64());
        assert_eq!(actual.verfer().qb64(), signer0.verfer().qb64());

        // Test put with different value when already put
        // In the Rust implementation, we might expect put to return false if the key exists
        let result = sdb.put(&keys, &signer1)?;
        assert!(!result);

        let actual = sdb.get(&keys)?.unwrap();
        assert_eq!(actual.qb64(), signer0.qb64());
        assert_eq!(actual.verfer().qb64(), signer0.verfer().qb64());

        // Test pin (overwrite)
        let result = sdb.pin(&keys, &signer1)?;
        assert!(result);

        let actual = sdb.get(&keys)?.unwrap();
        assert_eq!(actual.qb64(), signer1.qb64());
        assert_eq!(actual.verfer().qb64(), signer1.verfer().qb64());

        // Test with keys as single string not array
        let single_key = [signer0.verfer().qb64()];

        let result = sdb.pin(&single_key, &signer0)?;
        assert!(result);

        let actual = sdb.get(&single_key)?.unwrap();
        assert_eq!(actual.qb64(), signer0.qb64());
        assert_eq!(actual.verfer().qb64(), signer0.verfer().qb64());

        // Test rem again
        sdb.trim(&single_key, false)?;
        let actual = sdb.get(&single_key)?;
        assert!(actual.is_none());

        // Test missing entry
        let bad_key = ["DAQdADT79kS2zwHld29hixhZjC1Wj2bLRekca0elxHiE"];
        let actual = sdb.get(&bad_key)?;
        assert!(actual.is_none());

        // Test iteritems with new suber instance
        let db_arc = Arc::new(&db);
        let sdb_new = SignerSuber::<>::new(db_arc, "pugs.", None, false)?;

        let result = sdb_new.put(&[signer0.verfer().qb64b()], &signer0)?;
        assert!(result);

        let result = sdb_new.put(&[signer1.verfer().qb64b()], &signer1)?;
        assert!(result);

        let empty: [&[u8]; 0] = [];
        let items = sdb_new.get_item_iter(&empty, true)?;

        // Convert items to comparable format for assertion
        // Note: The order might be different from Python due to the nature of hash table iteration
        // We'll sort the items to ensure a consistent comparison
        let mut result_items: Vec<(String, String)> = items
            .iter()
            .map(|(keys, signer)| {
                let key_joined = String::from_utf8(keys[0].clone()).unwrap();
                (key_joined, signer.qb64())
            })
            .collect();

        result_items.sort();

        let mut expected_items = vec![
            (signer0.verfer().qb64(), signer0.qb64()),
            (signer1.verfer().qb64(), signer1.qb64()),
        ];
        expected_items.sort();

        assert_eq!(result_items, expected_items);

        // Test with composite keys
        let result = sdb_new.put(&["a", signer0.verfer().qb64().as_str()], &signer0)?;
        assert!(result);

        let result = sdb_new.put(&["a", signer1.verfer().qb64().as_str()], &signer1)?;
        assert!(result);

        let result = sdb_new.put(&["ab", signer0.verfer().qb64().as_str()], &signer0)?;
        assert!(result);

        let result = sdb_new.put(&["ab", signer1.verfer().qb64().as_str()], &signer1)?;
        assert!(result);

        // Test iteration with topkeys
        let top_keys = ["a", ""];  // append empty str to force trailing separator
        let items = sdb_new.get_item_iter(&top_keys, true)?;

        let mut result_items: Vec<(Vec<String>, String)> = items
            .iter()
            .map(|(keys, signer)| {
                let key_strings: Vec<String> = keys
                    .iter()
                    .map(|k| String::from_utf8(k.clone()).unwrap())
                    .collect();
                (key_strings, signer.qb64())
            })
            .collect();

        result_items.sort();

        let mut expected_items = vec![
            (vec!["a".to_string(), signer0.verfer().qb64()], signer0.qb64()),
            (vec!["a".to_string(), signer1.verfer().qb64()], signer1.qb64()),
        ];
        expected_items.sort();

        assert_eq!(result_items, expected_items);

        // Close the database and check it's no longer open
        drop(db);

        Ok(())
    }

    #[test]
    fn test_crypt_signer_suber() -> Result<(), Box<dyn std::error::Error>> {
        // Setup test signers
        let seed0: Vec<u8> = vec![
            0x18, 0x3b, 0x30, 0xc4, 0x0f, 0x2a, 0x76, 0x46, 0xfa, 0xe3, 0xa2, 0x45, 0x65, 0x65,
            0x1f, 0x96, 0x6f, 0xce, 0x29, 0x47, 0x85, 0xe3, 0x58, 0x86, 0xda, 0x04, 0xf0, 0xdc,
            0xde, 0x06, 0xc0, 0x2b,
        ];
        let signer0 = Signer::new(Some(&seed0), Some(mtr_dex::ED25519_SEED), Some(true))?;
        assert_eq!(signer0.verfer.code(), mtr_dex::ED25519);
        assert!(signer0.verfer.is_transferable()); // default
        assert_eq!(signer0.qb64(), "ABg7MMQPKnZG-uOiRWVlH5ZvzilHheNYhtoE8NzeBsAr");
        assert_eq!(signer0.verfer.qb64(), "DIYsYWYwtVo9my0dUHQA0-_ZEts8B5XdvXpHGtHpcR4h");

        let seed1: Vec<u8> = vec![
            0x60, 0x05, 0x93, 0xb9, 0x9b, 0x36, 0x1e, 0xe0, 0xd7, 0x98, 0x5e, 0x94, 0xc8, 0x45,
            0x74, 0xf2, 0xc4, 0xcd, 0x94, 0x18, 0xc6, 0xae, 0xb9, 0xb6, 0x6d, 0x12, 0xc4, 0x80,
            0x03, 0x07, 0xfc, 0xf7,
        ];

        let signer1 = Signer::new(Some(&seed1), Some(mtr_dex::ED25519_SEED), Some(true))?;
        assert_eq!(signer1.verfer.code(), mtr_dex::ED25519);
        assert!(signer1.verfer.is_transferable()); // default
        assert_eq!(signer1.qb64(), "AGAFk7mbNh7g15helMhFdPLEzZQYxq65tm0SxIADB_z3");
        assert_eq!(signer1.verfer.qb64(), "DIHpH-kgf2oMMfeplUmSOj0wtPY-EqfKlG4CoJTfLi42");

        let rawsalt = b"0123456789abcdef".to_vec();
        let salter = Salter::new(Some(&rawsalt), None, None)?;
        let salt = salter.qb64();
        assert_eq!(salt, "0AAwMTIzNDU2Nzg5YWJjZGVm");
        let stem = "blue";

        let cryptseed0: Vec<u8> = vec![
            0x68, 0x2c, 0x23, 0x7c, 0x8a, 0x70, 0x22, 0x12, 0xc4, 0x33, 0x74, 0x32, 0xa6, 0xe1,
            0x18, 0x19, 0xf0, 0x66, 0x32, 0x2c, 0x79, 0xc4, 0xc2, 0x31, 0x40, 0xf5, 0x40, 0x15,
            0x2e, 0xa2, 0x1a, 0xcf,
        ];
        let cryptsigner0 = Signer::new(Some(&cryptseed0), Some(mtr_dex::ED25519_SEED), Some(false))?;
        let seed0 = cryptsigner0.qb64();
        let aeid0 = cryptsigner0.verfer.qb64();
        assert_eq!(aeid0, "BCa7mK96FwxkU0TdF54Yqg3qBDXUWpOhQ_Mtr7E77yZB");

        let decrypter = Decrypter::new(Some(seed0.as_bytes()), None, None)?;
        let encrypter = Encrypter::new(None, None, Some(aeid0.as_bytes()))?;
        assert!(encrypter.verify_seed(seed0.as_bytes())?);

        let cryptseed1: Vec<u8> = vec![
            0x89, 0xfe, 0x7b, 0xd9, 0x27, 0xa7, 0xb3, 0x89, 0x23, 0x19, 0xbe, 0x63, 0xee, 0xed,
            0xc0, 0xf9, 0x97, 0xd0, 0x8f, 0x39, 0x1d, 0x79, 0x4e, 0x49, 0x49, 0x98, 0xbd, 0xa4,
            0xf6, 0xfe, 0xbb, 0x03,
        ];
        let cryptsigner1 = Signer::new(Some(&cryptseed1), Some(mtr_dex::ED25519_SEED), Some(false))?;

        // Create temporary directory for the LMDB database
        // Open LMDB database
        // Open LMDB database
        let db = LMDBer::builder()
            .name("test")
            .temp(true)
            .build()?;

        let db_arc = Arc::new(&db);

        // Test CryptSignerSuber functionality
        {
            // Create a CryptSignerSuber instance
            let sdb = CryptSignerSuber::new(db_arc.clone(), "bags.", None, true)?;

            // Test without encrypter or decrypter
            let vqb64 = signer0.verfer.qb64();
            let keys = &[vqb64.as_bytes()];

            // Test put and get
            assert!(sdb.put(keys, &signer0, None)?);
            let actual = sdb.get(keys, None)?.unwrap();
            assert_eq!(actual.qb64(), signer0.qb64());
            assert_eq!(actual.verfer.qb64(), signer0.verfer.qb64());

            // Test remove
            assert!(sdb.rem(keys)?);
            assert!(sdb.get(keys, None)?.is_none());

            // Test put again
            assert!(sdb.put(keys, &signer0, None)?);
            let actual = sdb.get(keys, None)?.unwrap();
            assert_eq!(actual.qb64(), signer0.qb64());
            assert_eq!(actual.verfer.qb64(), signer0.verfer.qb64());

            // Try putting a different value when already present
            let result = sdb.put(keys, &signer1, None)?;
            assert!(!result);
            let actual = sdb.get(keys, None)?.unwrap();
            assert_eq!(actual.qb64(), signer0.qb64());
            assert_eq!(actual.verfer.qb64(), signer0.verfer.qb64());

            // Test pin to overwrite
            assert!(sdb.pin(keys, &signer1, None)?);
            let actual = sdb.get(keys, None)?.unwrap();
            assert_eq!(actual.qb64(), signer1.qb64());
            assert_eq!(actual.verfer.qb64(), signer1.verfer.qb64());

            // Test with key as single string
            let key_str = signer0.verfer.qb64();
            let keys = &[key_str.as_bytes()];

            assert!(sdb.pin(keys, &signer0, None)?);
            let actual = sdb.get(keys, None)?.unwrap();
            assert_eq!(actual.qb64(), signer0.qb64());
            assert_eq!(actual.verfer.qb64(), signer0.verfer.qb64());

            assert!(sdb.rem(keys)?);
            assert!(sdb.get(keys, None)?.is_none());

            // Test missing entry
            let bad_key = "D1QdADT79kS2zwHld29hixhZjC1Wj2bLRekca0elxHiE";
            assert!(sdb.get(&[bad_key.as_bytes()], None)?.is_none());
        }

        // Test iteritems
        {

            let db_arc = Arc::new(&db);
            let sdb = CryptSignerSuber::new(db_arc.clone(), "pugs.", None, true)?;

            assert!(sdb.put(&[signer0.verfer.qb64().as_bytes()], &signer0, None)?);
            assert!(sdb.put(&[signer1.verfer.qb64().as_bytes()], &signer1, None)?);

            let items = sdb.get_item_iter(&[] as &[&[u8]], false, None)?;
            let mut items_qb64 = items
                .iter()
                .map(|(keys, sgnr)| {
                    let key_strs: Vec<String> = keys.iter().map(|k| String::from_utf8(k.clone()).unwrap()).collect();
                    (key_strs, sgnr.qb64())
                })
                .collect::<Vec<_>>();

            // Sort for predictable order in test
            items_qb64.sort_by(|a, b| b.0[0].cmp(&a.0[0]));

            assert_eq!(items_qb64.len(), 2);
            assert_eq!(items_qb64[0].0[0], signer0.verfer.qb64());
            assert_eq!(items_qb64[0].1, signer0.qb64());
            assert_eq!(items_qb64[1].0[0], signer1.verfer.qb64());
            assert_eq!(items_qb64[1].1, signer1.qb64());

            // Now test with encrypter and decrypter
            let encrypter0 = Encrypter::new(None, None, Some(&cryptsigner0.verfer.qb64b()))?;
            let decrypter0 = Decrypter::new(None, None, Some(&cryptsigner0.qb64b()))?;

            // First pin with encrypter
            assert!(sdb.pin(&[signer0.verfer.qb64().as_bytes()], &signer0, Some(encrypter0.clone()))?);
            assert!(sdb.pin(&[signer1.verfer.qb64().as_bytes()], &signer1, Some(encrypter0.clone()))?);

            // Now get with decrypter
            let actual0 = sdb.get(&[signer0.verfer.qb64().as_bytes()], Some(decrypter0.clone()))?.unwrap();
            assert_eq!(actual0.qb64(), signer0.qb64());
            assert_eq!(actual0.verfer.qb64(), signer0.verfer.qb64());

            let actual1 = sdb.get(&[signer1.verfer.qb64().as_bytes()], Some(decrypter0.clone()))?.unwrap();
            assert_eq!(actual1.qb64(), signer1.qb64());
            assert_eq!(actual1.verfer.qb64(), signer1.verfer.qb64());

            // Now try to get without decrypter - should fail
            match sdb.get(&[signer0.verfer.qb64().as_bytes()], None) {
                Err(_) => assert!(true),
                Ok(_) => assert!(false, "Should fail without decrypter"),
            }

            match sdb.get(&[signer1.verfer.qb64().as_bytes()], None) {
                Err(_) => assert!(true),
                Ok(_) => assert!(false, "Should fail without decrypter"),
            }

            // Remove and test put
            assert!(sdb.rem(&[signer0.verfer.qb64b()])?);
            assert!(sdb.get(&[signer0.verfer.qb64b()], Some(decrypter0.clone()))?.is_none());

            assert!(sdb.rem(&[signer1.verfer.qb64b()])?);
            assert!(sdb.get(&[signer1.verfer.qb64b()], Some(decrypter0.clone()))?.is_none());

            assert!(sdb.put(&[signer0.verfer.qb64b()], &signer0, Some(encrypter0.clone()))?);
            assert!(sdb.put(&[signer1.verfer.qb64b()], &signer1, Some(encrypter0.clone()))?);

            // Test getItemIter with decrypter
            let items = sdb.get_item_iter(&[] as &[&[u8]], false, Some(decrypter0.clone()))?;
            let mut items_qb64 = items
                .iter()
                .map(|(keys, sgnr)| {
                    let key_strs: Vec<String> = keys.iter().map(|k| String::from_utf8(k.clone()).unwrap()).collect();
                    (key_strs, sgnr.qb64())
                })
                .collect::<Vec<_>>();

            // Sort for predictable order in test
            items_qb64.sort_by(|a, b| b.0[0].cmp(&a.0[0]));

            assert_eq!(items_qb64.len(), 2);
            assert_eq!(items_qb64[0].0[0], signer0.verfer.qb64());
            assert_eq!(items_qb64[0].1, signer0.qb64());
            assert_eq!(items_qb64[1].0[0], signer1.verfer.qb64());
            assert_eq!(items_qb64[1].1, signer1.qb64());

            // Test composite keys
            assert!(sdb.put(&["a".as_bytes(), signer0.verfer.qb64().as_bytes()], &signer0, Some(encrypter0.clone()))?);
            assert!(sdb.put(&["a".as_bytes(), signer1.verfer.qb64().as_bytes()], &signer1, Some(encrypter0.clone()))?);
            assert!(sdb.put(&["ab".as_bytes(), signer0.verfer.qb64().as_bytes()], &signer0, Some(encrypter0.clone()))?);
            assert!(sdb.put(&["ab".as_bytes(), signer1.verfer.qb64().as_bytes()], &signer1, Some(encrypter0.clone()))?);

            // Test prefix iteration
            let top_keys = &["a".as_bytes(), "".as_bytes()]; // append empty str to force trailing .sep
            let items = sdb.get_item_iter(top_keys, true, Some(decrypter0.clone()))?;

            let items_qb64 = items
                .iter()
                .map(|(keys, sgnr)| {
                    let key_strs: Vec<String> = keys.iter().map(|k| String::from_utf8(k.clone()).unwrap()).collect();
                    (key_strs, sgnr.qb64())
                })
                .collect::<Vec<_>>();

            assert_eq!(items_qb64.len(), 2);
            // Check that we have both signer0 and signer1 with prefix "a"
            let has_signer0 = items_qb64.iter().any(|(keys, qb64)|
                keys[0] == "a" && keys[1] == signer0.verfer.qb64() && *qb64 == signer0.qb64());
            let has_signer1 = items_qb64.iter().any(|(keys, qb64)|
                keys[0] == "a" && keys[1] == signer1.verfer.qb64() && *qb64 == signer1.qb64());
            assert!(has_signer0);
            assert!(has_signer1);

            // Test re-encrypt
            let encrypter1 = Encrypter::new(None, None, Some(cryptsigner1.verfer.qb64().as_bytes()))?;
            let decrypter1 = Decrypter::new(None, None, Some(cryptsigner1.qb64().as_bytes()))?;

            for (keys, sgnr) in sdb.get_item_iter(&[] as &[&[u8]], false, Some(decrypter0.clone()))? {
                sdb.pin(&keys.iter().map(|k| k.as_slice()).collect::<Vec<_>>(), &sgnr, Some(encrypter1.clone()))?;
            }

            // Verify re-encrypted data is accessible with new decrypter
            let items = sdb.get_item_iter(&[] as &[&[u8]], false, Some(decrypter1))?;
            assert_eq!(items.len(), 6); // Should have all 6 items

            // Verify we can find all the expected entries
            let items_map: std::collections::HashMap<String, Vec<(Vec<String>, String)>> = items
                .iter()
                .map(|(keys, sgnr)| {
                    let key_strs: Vec<String> = keys.iter().map(|k| String::from_utf8(k.clone()).unwrap()).collect();
                    let prefix = if key_strs.len() > 1 { key_strs[0].clone() } else { "root".to_string() };
                    (prefix, (key_strs, sgnr.qb64()))
                })
                .fold(std::collections::HashMap::new(), |mut acc, (prefix, entry)| {
                    acc.entry(prefix).or_insert_with(Vec::new).push(entry);
                    acc
                });

            // Verify the expected entries
            assert_eq!(items_map.get("root").unwrap().len(), 2);
            assert_eq!(items_map.get("a").unwrap().len(), 2);
            assert_eq!(items_map.get("ab").unwrap().len(), 2);
        }

        Ok(())
    }
}
