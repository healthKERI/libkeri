use crate::keri::core::serdering::{Rawifiable, Serder, SerderACDC, SerderKERI};
use crate::keri::db::dbing::{BytesDatabase, LMDBer};
use crate::keri::db::errors::DBError;
use crate::keri::db::subing::{SuberError, ValueCodec};
use std::marker::PhantomData;
use std::sync::Arc;

/// A codec for serializing and deserializing Serder instances
pub struct SerderCodec<S: Serder + 'static> {
    verify: bool,
    _serder_type: PhantomData<S>,
}

impl<S: Serder + 'static> SerderCodec<S> {
    pub fn new(verify: bool) -> Self {
        Self {
            verify,
            _serder_type: PhantomData,
        }
    }
}

impl<S: Serder + 'static> ValueCodec for SerderCodec<S> {
    type Error = SuberError;

    fn serialize<T: ?Sized + Clone + Into<Vec<u8>>>(val: &T) -> Result<Vec<u8>, SuberError> {
        // For Serder instances, we use the raw bytes
        Ok(val.clone().into())
    }

    fn deserialize<T: TryFrom<Vec<u8>>>(bytes: &[u8]) -> Result<T, SuberError> {
        // This is a placeholder. The actual implementation will come from the SerderSuberBase
        Err(SuberError::DeserializationError(
            "Direct deserialization not implemented".to_string(),
        ))
    }
}

/// A struct for handling serialized Serder instances in a database
pub struct SerderSuberBase<'db, S: Serder + Rawifiable + 'static> {
    db: Arc<&'db LMDBer>,         // The base LMDB database
    sdb: BytesDatabase,           // The sub-database
    sep: u8,                      // Separator for combining keys
    verify: bool,                 // Whether to verify data when deserializing
    _serder_type: PhantomData<S>, // Track the Serder type
}

impl<'db, S: Serder + Rawifiable + 'static> SerderSuberBase<'db, S> {
    /// Create a new SerderSuberBase instance
    pub fn new(
        db: Arc<&'db LMDBer>,
        subkey: &str,
        sep: Option<u8>,
        verify: bool,
    ) -> Result<Self, SuberError> {
        let sdb = db.create_database(Some(subkey), Some(false))?;

        Ok(Self {
            db,
            sdb,
            sep: sep.unwrap_or(b'.'),
            verify,
            _serder_type: PhantomData,
        })
    }

    /// Convert various key forms to bytes
    pub fn to_key<K: AsRef<[u8]>>(&self, keys: &[K], topive: bool) -> Vec<u8> {
        // Same implementation as SuberBase
        let mut result = Vec::new();

        // If there's only one key and it's already bytes, return it directly
        if keys.len() == 1 {
            let key = keys[0].as_ref();
            if !topive {
                return key.to_vec();
            }
            // For topive=true, append separator
            result.extend_from_slice(key);
            result.push(self.sep);
            return result;
        }

        // Join multiple keys with separators
        for (i, key) in keys.iter().enumerate() {
            if i > 0 {
                result.push(self.sep);
            }
            result.extend_from_slice(key.as_ref());
        }

        // Add trailing separator for topive
        if topive && (!result.is_empty() && result[result.len() - 1] != self.sep) {
            result.push(self.sep);
        }

        result
    }

    /// Convert a key to a vector of key parts
    pub fn to_keys(&self, key: &[u8]) -> Vec<Vec<u8>> {
        // Same implementation as SuberBase
        key.split(|&b| b == self.sep)
            .map(|part| part.to_vec())
            .collect()
    }

    /// Serialize a Serder to bytes
    fn ser(&self, val: &S) -> Vec<u8> {
        // For Serder instances, we just use the raw bytes
        val.raw().to_vec()
    }

    /// Deserialize bytes to a Serder
    fn des(&self, val: &[u8]) -> Result<S, SuberError> {
        // Create a Serder instance from the raw bytes
        S::from_raw(val, None).map_err(|e| {
            SuberError::DeserializationError(format!("Failed to deserialize Serder: {}", e))
        })
    }

    /// Get a serder value by key
    pub fn get<K: AsRef<[u8]>>(&self, keys: &[K]) -> Result<Option<S>, SuberError> {
        let key = self.to_key(keys, false);

        if let Some(val) = self.db.get_val(&self.sdb, &key)? {
            // Create the Serder instance from raw bytes
            let serder = self.des(&val)?;

            Ok(Some(serder))
        } else {
            Ok(None)
        }
    }

    /// Put a serder value at keys (doesn't overwrite)
    pub fn put<K: AsRef<[u8]>>(&self, keys: &[K], val: &S) -> Result<bool, SuberError> {
        let key = self.to_key(keys, false);
        let val_bytes = self.ser(val);

        Ok(self.db.put_val(&self.sdb, &key, &val_bytes)?)
    }

    /// Pin (set) a serder value at keys (overwrites)
    pub fn pin<K: AsRef<[u8]>>(&self, keys: &[K], val: &S) -> Result<bool, SuberError> {
        let key = self.to_key(keys, false);
        let val_bytes = self.ser(val);

        Ok(self.db.set_val(&self.sdb, &key, &val_bytes)?)
    }

    /// Remove an entry at keys
    pub fn rem<K: AsRef<[u8]>>(&self, keys: &[K]) -> Result<bool, SuberError> {
        let key = self.to_key(keys, false);
        Ok(self.db.del_val(&self.sdb, &key)?)
    }

    /// Remove entries with keys starting with a prefix
    pub fn trim<K: AsRef<[u8]>>(&self, keys: &[K], topive: bool) -> Result<bool, SuberError> {
        let key = self.to_key(keys, topive);
        Ok(self.db.del_top_val(&self.sdb, &key)?)
    }

    /// Iterator for full items (with all parts visible)
    pub fn get_full_item_iter<K: AsRef<[u8]>>(
        &self,
        keys: &[K],
        topive: bool,
    ) -> Result<Vec<(Vec<Vec<u8>>, S)>, SuberError> {
        let key = self.to_key(keys, topive);

        let mut result = Vec::new();
        self.db.get_top_items_iter(&self.sdb, &key, |k, v| {
            // Create the Serder instance from raw bytes
            let serder = match self.des(v) {
                Ok(s) => s,
                Err(e) => {
                    return Err(DBError::ValueError(format!(
                        "Failed to deserialize Serder: {}",
                        e
                    )))
                }
            };

            result.push((self.to_keys(k), serder));
            Ok(true) // Continue iteration for all items
        })?;

        Ok(result)
    }

    /// Iterator for normal items (hiding implementation details)
    pub fn get_item_iter<K: AsRef<[u8]>>(
        &self,
        keys: &[K],
        topive: bool,
    ) -> Result<Vec<(Vec<Vec<u8>>, S)>, SuberError> {
        // By default, this is the same as get_full_item_iter
        self.get_full_item_iter(keys, topive)
    }

    /// Count all items in the database
    pub fn cnt_all(&self) -> Result<usize, SuberError> {
        Ok(self.db.cnt(&self.sdb)?)
    }
}

/// SerderSuber is a specialized database class for storing and retrieving Serder instances.
/// It combines the functionality of SerderSuberBase and Suber.
pub struct SerderSuber<'db, S: Serder + Rawifiable + 'static> {
    base: SerderSuberBase<'db, S>,
}

impl<'db, S: Serder + Rawifiable + 'static> SerderSuber<'db, S> {
    /// Create a new SerderSuber instance
    pub fn new(
        db: Arc<&'db LMDBer>,
        subkey: &str,
        sep: Option<u8>,
        verify: bool,
    ) -> Result<Self, SuberError> {
        let base = SerderSuberBase::new(db, subkey, sep, verify)?;
        Ok(Self { base })
    }

    /// Put a serder value at keys (doesn't overwrite)
    /// Returns true if put, false if key already exists
    pub fn put<K: AsRef<[u8]>>(&self, keys: &[K], val: &S) -> Result<bool, SuberError> {
        self.base.put(keys, val)
    }

    /// Pin (set) a serder value at keys (overwrites)
    /// Returns true if successful
    pub fn pin<K: AsRef<[u8]>>(&self, keys: &[K], val: &S) -> Result<bool, SuberError> {
        self.base.pin(keys, val)
    }

    /// Get a serder value by key
    /// Returns Some(S) if found, None if not found
    pub fn get<K: AsRef<[u8]>>(&self, keys: &[K]) -> Result<Option<S>, SuberError> {
        self.base.get(keys)
    }

    /// Remove an entry at keys
    /// Returns true if removed, false if not found
    pub fn rem<K: AsRef<[u8]>>(&self, keys: &[K]) -> Result<bool, SuberError> {
        self.base.rem(keys)
    }

    /// Remove entries with keys starting with a prefix
    /// Returns true if any entries were removed
    pub fn trim<K: AsRef<[u8]>>(&self, keys: &[K], topive: bool) -> Result<bool, SuberError> {
        self.base.trim(keys, topive)
    }

    /// Iterator for full items (with all parts visible)
    pub fn get_full_item_iter<K: AsRef<[u8]>>(
        &self,
        keys: &[K],
        topive: bool,
    ) -> Result<Vec<(Vec<Vec<u8>>, S)>, SuberError> {
        self.base.get_full_item_iter(keys, topive)
    }

    /// Iterator for normal items (hiding implementation details)
    pub fn get_item_iter<K: AsRef<[u8]>>(
        &self,
        keys: &[K],
        topive: bool,
    ) -> Result<Vec<(Vec<Vec<u8>>, S)>, SuberError> {
        self.base.get_item_iter(keys, topive)
    }

    /// Count all items in the database
    pub fn cnt_all(&self) -> Result<usize, SuberError> {
        self.base.cnt_all()
    }
}

/// A type alias for common usage with SerderKERI
pub type SerderKERISuber<'db> = SerderSuber<'db, SerderKERI>;
pub type SerderACDCSuber<'db> = SerderSuber<'db, SerderACDC>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keri::core::serdering::SerderKERI;
    use crate::keri::db::dbing::LMDBer;
    use std::sync::Arc;

    #[test]
    fn test_serder_suber() -> Result<(), SuberError> {
        // Create a temporary database for testing
        let lmdber = LMDBer::builder()
            .name("test_serder_db")
            .temp(true)
            .build()?;
        let db = Arc::new(&lmdber);

        // Create a SerderSuber instance
        let suber: SerderSuber<SerderKERI> = SerderSuber::new(db, "serders.", None, false)?;

        // Create a test SerderKERI
        let sample_ked = r#"{"v":"KERI10JSON00012b_","t":"icp","d":"EDkU2U_TPKca14VElEItpj7twohQL60GIaUPvSHAghga","i":"EDkU2U_TPKca14VElEItpj7twohQL60GIaUPvSHAghga","s":"0","kt":"1","k":["DLcVCJsrp_z4To1j52pggULYa_PEs2sCZggVJ3jBUFeI"],"nt":"1","n":["EA1P0H2qNRf_685xnztMESEs36hwWBTTQmwVrZr5qGyQ"],"bt":"0","b":[],"c":[],"a":[]}"#;
        let serder =
            SerderKERI::from_raw(sample_ked.as_ref(), None).expect("Failed to parse test Serder");

        // Test putting and getting a serder
        let keys = &["test_key".as_bytes()];
        suber.put(keys, &serder)?;

        let retrieved = suber.get(keys)?;
        assert!(retrieved.is_some());

        let retrieved_serder = retrieved.unwrap();
        assert_eq!(retrieved_serder.raw(), serder.raw());

        // Test overwrite with pin
        let sample_ked2 = r#"{"v":"KERI10JSON000160_","t":"rot","d":"EG22BBFSLnRRZHHxoAlFP2Kc5j9xyg-1sSkMEgGVcRlD","i":"EFa1wAk_coghxxGCID6jEN79Kmvyj0Y1wWN_ndUv3LjW","s":"1","p":"EFa1wAk_coghxxGCID6jEN79Kmvyj0Y1wWN_ndUv3LjW","kt":"1","k":["DAceoFXtYpYjyKGLLfv0Hs4YSGQtqmzKx64zfMI9fBUM"],"nt":"1","n":["EPwseSLvRsbjHDUGeZJSed0HF_Myw8qvZksRTQBC2cjO"],"bt":"0","br":[],"ba":[],"a":[]}"#;
        let serder2 =
            SerderKERI::from_raw(sample_ked2.as_ref(), None).expect("Failed to parse test Serder");

        // First attempt with put (should fail to overwrite)
        let result = suber.put(keys, &serder2)?;
        assert!(!result); // Should return false because key exists

        // Get and verify it's still the original
        let retrieved = suber.get(keys)?.unwrap();
        assert_eq!(retrieved.raw(), serder.raw());

        // Now use pin to overwrite
        let result = suber.pin(keys, &serder2)?;
        assert!(result);

        // Get and verify it's the new value
        let retrieved = suber.get(keys)?.unwrap();
        assert_eq!(retrieved.raw(), serder2.raw());

        // Test removing an entry
        let result = suber.rem(keys)?;
        assert!(result);

        let retrieved = suber.get(keys)?;
        assert!(retrieved.is_none());

        // Test adding multiple entries and using iterators
        let serders = [
            (vec!["a", "1"], serder.clone()),
            (vec!["a", "2"], serder2.clone()),
        ];

        for (k, s) in &serders {
            let key_bytes: Vec<&[u8]> = k.iter().map(|s| s.as_bytes()).collect();
            suber.put(&key_bytes, s)?;
        }

        // Test get_item_iter
        let iter_keys = &["a".as_bytes()];
        let items = suber.get_item_iter(iter_keys, true)?;

        assert_eq!(items.len(), 2);

        // Test cnt_all
        let count = suber.cnt_all()?;
        assert_eq!(count, 2);

        // Test trim
        suber.trim(iter_keys, true)?;
        let count = suber.cnt_all()?;
        assert_eq!(count, 0);

        Ok(())
    }
}
