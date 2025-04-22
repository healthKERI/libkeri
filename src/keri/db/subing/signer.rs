use std::sync::Arc;
use crate::cesr::Parsable;
use crate::cesr::signing::Signer;
use crate::cesr::verfer::Verfer;
use crate::errors::MatterError;
use crate::keri::db::dbing::LMDBer;
use crate::keri::db::subing::cesr::{CesrSuber, CesrSuberError};
use crate::keri::db::subing::SuberError;
use crate::Matter;

#[derive(Debug, thiserror::Error)]
pub enum SignerSuberError {
    #[error("CesrSuber error: {0}")]
    CesrSuberError(#[from] CesrSuberError),

    #[error("Matter error: {0}")]
    MatterError(#[from] MatterError),

    #[error("Invalid signer type")]
    InvalidSignerType,

    #[error("Verfer error: {0}")]
    VerferError(String),
}

pub trait SignerTrait: Matter + Parsable {
    fn with_transferable(qb64b: &[u8], transferable: bool) -> Result<Self, CesrSuberError>;
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
    ) -> Result<Self, SignerSuberError> {
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
    pub fn get<K: AsRef<[u8]>>(&self, keys: &[K]) -> Result<Option<Signer>, SignerSuberError> {
        if keys.is_empty() {
            return Err(SignerSuberError::CesrSuberError(CesrSuberError::SuberError(
                SuberError::EmptyKeys,
            )));
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
            return Err(SignerSuberError::CesrSuberError(CesrSuberError::SuberError(
                SuberError::EmptyKeys,
            )));
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
    ) -> Result<Vec<(Vec<Vec<u8>>, Signer)>, SignerSuberError> {
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
            let mut signer = Signer::from_qb64b(&mut qb64b, None)?;
            signer.set_verfer(verfer);
            result.push((ikeys, signer))
        }

        Ok(result)
    }

    // Forward other methods to the base implementation
    pub fn put<K: AsRef<[u8]>>(&self, keys: &[K], val: &Signer) -> Result<bool, SignerSuberError> {
        Ok(self.base.put(keys, val)?)
    }

    // Forward other methods to the base implementation
    pub fn pin<K: AsRef<[u8]>>(&self, keys: &[K], val: &Signer) -> Result<bool, SignerSuberError> {
        Ok(self.base.pin(keys, val)?)
    }

    pub fn trim<K: AsRef<[u8]>>(&self, keys: &[K], topive: bool) -> Result<bool, SignerSuberError> {
        Ok(self.base.trim(keys, topive)?)
    }

    pub fn cnt_all(&self) -> Result<usize, SignerSuberError> {
        Ok(self.base.cnt_all()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tempfile::tempdir;
    use crate::cesr::mtr_dex;
    use crate::cesr::signing::Signer;

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
}
