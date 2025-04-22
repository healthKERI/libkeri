use std::marker::PhantomData;
use std::sync::Arc;
use crate::cesr::Parsable;
use crate::keri::db::dbing::{BytesDatabase, LMDBer};
use crate::keri::db::errors::DBError;
use crate::keri::db::subing::{SuberBase, SuberError, ValueCodec};
use crate::cesr::Matter;

// CesrCodec implements ValueCodec trait for CESR objects
pub struct CesrCodec<T: Matter> {
    _phantom: PhantomData<T>,
}

impl<T: Matter> ValueCodec for CesrCodec<T> {
    type Error = SuberError;

    fn serialize<V: ?Sized + Clone + Into<Vec<u8>>>(val: &V) -> Result<Vec<u8>, SuberError> {
        // In the case of Matter objects, we should use qb64b
        // But this is a generic function that can receive other types
        // We'll assume val can be converted to Vec<u8>
        Ok(val.clone().into())
    }

    fn deserialize<V: TryFrom<Vec<u8>>>(bytes: &[u8]) -> Result<V, SuberError> {
        // Generic deserialization using TryFrom
        match V::try_from(bytes.to_vec()) {
            Ok(v) => Ok(v),
            Err(_) => Err(SuberError::DeserializationError(
                "Failed to deserialize value".to_string(),
            )),
        }
    }
}

// The actual CesrSuberBase implementation
pub struct CesrSuberBase<'db, M: Matter> {
    base: SuberBase<'db, CesrCodec<M>>,
    _matter_type: PhantomData<M>,
}

impl<'db, M: Matter + Parsable> CesrSuberBase<'db, M> {
    pub fn new(
        db: Arc<&'db LMDBer>,
        subkey: &str,
        sep: Option<u8>,
        verify: bool,
    ) -> Result<Self, SuberError> {
        let base = SuberBase::<'db, CesrCodec<M>>::new(db, subkey, sep, verify)?;

        Ok(Self {
            base,
            _matter_type: PhantomData,
        })
    }

    // Override ser method to use Matter's qb64b method
    pub fn ser(&self, val: &M) -> Result<Vec<u8>, SuberError> {
        Ok(val.qb64b())
    }

    // Override des method to use Matter's from_qb64b method
    pub fn des(&self, val: &[u8]) -> Result<M, SuberError> {
        Ok(M::from_qb64b(&mut val.to_vec(), None)?)
    }

    pub fn to_key<K: AsRef<[u8]>>(&self, keys: &[K], topive: bool) -> Vec<u8> {
        self.base.to_key(keys, topive)
    }

    // Delegate methods to the base implementation
    pub fn put<K: AsRef<[u8]>>(&self, keys: &[K], val: &M) -> Result<bool, SuberError> {
        let key = self.base.to_key(keys, false);
        let val_bytes = self.ser(val)?;
        Ok(self.base.db.put_val(&self.base.sdb, &key, &val_bytes)?)
    }

    pub fn put_val(&self, key: &[u8], val: &[u8]) -> Result<bool, DBError> {
        self.base.db.put_val(&self.base.sdb, key, val)
    }

    pub fn set_val(&self, key: &[u8], val: &[u8]) -> Result<bool, DBError> {
        self.base.db.set_val(&self.base.sdb, key, val)
    }

    // Delegate methods to the base implementation
    pub fn pin<K: AsRef<[u8]>>(&self, keys: &[K], val: &M) -> Result<bool, SuberError> {
        let key = self.base.to_key(keys, false);
        let val_bytes = self.ser(val)?;
        Ok(self.base.db.set_val(&self.base.sdb, &key, &val_bytes)?)
    }

    pub fn get<K: AsRef<[u8]>>(&self, keys: &[K]) -> Result<Option<M>, SuberError> {
        let key = self.base.to_key(keys, false);
        if let Some(val) = self.base.db.get_val(&self.base.sdb, &key)? {
            Ok(Some(self.des(&val)?))
        } else {
            Ok(None)
        }
    }

    // Remove an entry at keys
    pub fn rem<K: AsRef<[u8]>>(&self, keys: &[K]) -> Result<bool, SuberError> {
        self.base.trim(keys, false)
    }

    // Delegate the remaining methods to base
    pub fn trim<K: AsRef<[u8]>>(&self, keys: &[K], topive: bool) -> Result<bool, SuberError> {
        Ok(self.base.trim(keys, topive)?)
    }

    pub fn get_full_item_iter<K: AsRef<[u8]>>(
        &self,
        keys: &[K],
        topive: bool,
    ) -> Result<Vec<(Vec<Vec<u8>>, Vec<u8>)>, SuberError> {
        Ok(self.base.get_full_item_iter(keys, topive)?)
    }

    pub fn get_item_iter<K: AsRef<[u8]>>(
        &self,
        keys: &[K],
        topive: bool,
    ) -> Result<Vec<(Vec<Vec<u8>>, Vec<u8>)>, SuberError> {
        Ok(self.base.get_item_iter(keys, topive)?)
    }

    pub fn cnt_all(&self) -> Result<usize, SuberError> {
        Ok(self.base.cnt_all()?)
    }

    // Add additional methods that would transform raw byte values into Matter instances
    pub fn process_items(&self, items: Vec<(Vec<Vec<u8>>, Vec<u8>)>) -> Result<Vec<(Vec<Vec<u8>>, M)>, SuberError> {
        items
            .into_iter()
            .map(|(keys, val)| {
                let matter = self.des(&val)?;
                Ok((keys, matter))
            })
            .collect()
    }
}

// Similar to the Python Suber class, we can implement a wrapper for CesrSuberBase
pub struct CesrSuber<'db, M: Matter> {
    base: CesrSuberBase<'db, M>,
}

impl<'db, M: Matter + Parsable> CesrSuber<'db, M> {
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
    pub fn pin<K: AsRef<[u8]>>(&self, keys: &[K], val: &M) -> Result<bool, SuberError> {
        self.base.pin(keys, val)
    }

    // Delegate all methods to the base
    pub fn put<K: AsRef<[u8]>>(&self, keys: &[K], val: &M) -> Result<bool, SuberError> {
        self.base.put(keys, val)
    }

    pub fn get<K: AsRef<[u8]>>(&self, keys: &[K]) -> Result<Option<M>, SuberError> {
        self.base.get(keys)
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

    pub fn get_item_iter<K: AsRef<[u8]>>(
        &self,
        keys: &[K],
        topive: bool,
    ) -> Result<Vec<(Vec<Vec<u8>>, Vec<u8>)>, SuberError> {
        self.base.get_item_iter(keys, topive)
    }

    pub fn process_items(&self, items: Vec<(Vec<Vec<u8>>, Vec<u8>)>) -> Result<Vec<(Vec<Vec<u8>>, M)>, SuberError> {
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

    use crate::cesr::{BaseMatter, Matter};
    use crate::cesr::diger::Diger;
    use crate::cesr::indexing::siger::Siger;
    use crate::keri::db::dbing::LMDBer;
    use crate::keri::db::subing::cesr::CesrSuber;

    #[test]
    fn test_cesr_suber() -> Result<(), SuberError> {
        // Create a temporary database for testing
        let lmdber = LMDBer::builder()
            .name("test_db")
            .temp(true)
            .build()?;

        // Create "seen." database
        assert_eq!(lmdber.name(), "test_db");
        assert!(lmdber.opened());

        let db_ref = Arc::new(&lmdber);

        // Create CesrSuber with default Matter class
        let sdb = CesrSuber::<BaseMatter>::new(db_ref, "bags.", None, true)?;

        // Test with initial value
        let pre0 = "BDzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc";
        let val0 = BaseMatter::from_qb64(pre0)?;

        // Test keys as tuple
        let keys: &[&[u8]] = &[b"alpha".as_ref(), b"dog".as_ref()];

        // Test put operation
        let result = sdb.put(keys, &val0)?;
        assert!(result);

        // Test get operation
        let actual = sdb.get(keys)?.unwrap();
        assert_eq!(actual.qb64(), val0.qb64());

        // Test trim (remove) operation
        let result = sdb.trim(keys, false)?;
        assert!(result);

        // Verify the entry is removed
        let actual = sdb.get(keys)?;
        assert!(actual.is_none());

        // Put again and verify
        let result = sdb.put(keys, &val0)?;
        assert!(result);

        let actual = sdb.get(keys)?.unwrap();
        assert_eq!(actual.qb64(), val0.qb64());

        // Attempt to put a different value (pin without force should fail)
        let pre1 = "BHHzqZWzwE-Wk7K0gzQPYGGwTmuupUhPx5_y1x4ejhcc";
        let val1 = BaseMatter::from_qb64(pre1)?;

        // This should fail because it's not a forced update (equivalent to Python's put returning False)
        let result = sdb.put(keys, &val1)?;
        assert!(!result);

        // Original value should still be there
        let actual = sdb.get(keys)?.unwrap();
        assert_eq!(actual.qb64(), val0.qb64());

        // Force update with pin operation (trim and put)
        // In our Rust implementation, this would be a trim followed by a put
        let trim_result = sdb.trim(keys, false)?;
        assert!(trim_result);

        let put_result = sdb.put(keys, &val1)?;
        assert!(put_result);

        let actual = sdb.get(keys)?.unwrap();
        assert_eq!(actual.qb64(), val1.qb64());

        // Test with keys as string
        let keys_str: &[&[u8]] = &[b"beta.fish".as_ref()];

        let result = sdb.put(keys_str, &val1)?;
        assert!(result);

        let actual = sdb.get(keys_str)?.unwrap();
        assert_eq!(actual.qb64(), val1.qb64());

        let result = sdb.trim(keys_str, false)?;
        assert!(result);

        let actual = sdb.get(keys_str)?;
        assert!(actual.is_none());

        // Test missing entry
        let bad_key: &[&[u8]] = &[b"badkey".as_ref()];
        let actual = sdb.get(bad_key)?;
        assert!(actual.is_none());

        // Test iteritems (get_item_iter)
        let db_ref = Arc::new(&lmdber);
        let sdb_pugs = CesrSuber::<BaseMatter>::new(db_ref, "pugs.", None, true)?;

        let keys_a1: &[&[u8]] = &[b"a".as_ref(), b"1".as_ref()];
        let keys_a2: &[&[u8]] = &[b"a".as_ref(), b"2".as_ref()];

        assert!(sdb_pugs.put(keys_a1, &val0)?);
        assert!(sdb_pugs.put(keys_a2, &val1)?);

        let empty: [&[u8]; 0] = [];
        let items = sdb_pugs.get_item_iter(&empty, false)?;
        let processed_items = sdb_pugs.process_items(items)?;

        // Convert the result to a format we can easily check
        let mut result_items = Vec::new();
        for (keys_vec, val) in processed_items {
            let keys_tuple: Vec<String> = keys_vec.into_iter()
                .map(|k| {
                    String::from_utf8(k).unwrap()
                })
                .collect();

            result_items.push((keys_tuple, val.qb64()));
        }

        // Check the iteritems result
        assert_eq!(result_items.len(), 2);
        assert_eq!(result_items[0].0, vec!["a".to_string(), "1".to_string()]);
        assert_eq!(result_items[0].1, val0.qb64());
        assert_eq!(result_items[1].0, vec!["a".to_string(), "2".to_string()]);
        assert_eq!(result_items[1].1, val1.qb64());

        // Test with Diger class
        let db_ref = Arc::new(&lmdber);
        let sdb_diger = CesrSuber::<Diger>::new(db_ref, "pigs.", None, true)?;

        let dig0 = "EAPYGGwTmuupWzwEHHzq7K0gzUhPx5_yZ-Wk1x4ejhcc";
        let val0 = Diger::from_qb64(dig0)?;

        let keys: &[&[u8]] = &[b"alpha".as_ref(), b"dog".as_ref()];

        assert!(sdb_diger.put(keys, &val0)?);

        let actual = sdb_diger.get(keys)?.unwrap();
        assert_eq!(actual.qb64(), val0.qb64());

        assert!(sdb_diger.trim(keys, false)?);

        let actual = sdb_diger.get(keys)?;
        assert!(actual.is_none());

        assert!(sdb_diger.put(keys, &val0)?);

        let actual = sdb_diger.get(keys)?.unwrap();
        assert_eq!(actual.qb64(), val0.qb64());

        // Attempt to update with a Matter value that has a different code
        let pre1 = "EHHzqZWzwE-Wk7K0gzQPYGGwTmuupUhPx5_y1x4ejhcc";
        let val1 = BaseMatter::from_qb64(pre1)?;

        // In Rust the following won't compile(!) because we're trying to add a different type
        // let result = sdb_diger.put(keys, &val1).unwrap();
        // assert!(!result);

        // Force update with pin operation (trim and put)
        let trim_result = sdb_diger.trim(keys, false)?;
        assert!(trim_result);

        let val1_diger = Diger::from_qb64(pre1)?;
        let put_result = sdb_diger.put(keys, &val1_diger)?;
        assert!(put_result);

        let actual = sdb_diger.get(keys)?.unwrap();
        assert_eq!(actual.qb64(), val1_diger.qb64());

        // Test iteritems with another database
        let db_ref = Arc::new(&lmdber);
        let sdb_figs = CesrSuber::<Diger>::new(db_ref, "figs.", None, true)?;

        let keys_a1: &[&[u8]] = &[b"a".as_ref(), b"1".as_ref()];
        let keys_a2: &[&[u8]] = &[b"a".as_ref(), b"2".as_ref()];

        assert!(sdb_figs.put(keys_a1, &val0)?);
        assert!(sdb_figs.put(keys_a2, &val1_diger)?);

        let items = sdb_figs.get_item_iter(&empty, false)?;
        let processed_items = sdb_figs.process_items(items)?;

        let mut result_items = Vec::new();
        for (keys_vec, val) in processed_items {
            let keys_tuple: Vec<String> = keys_vec.into_iter()
                .map(|k| String::from_utf8(k).unwrap())
                .collect();

            result_items.push((keys_tuple, val.qb64()));
        }

        assert_eq!(result_items.len(), 2);
        assert_eq!(result_items[0].0, vec!["a".to_string(), "1".to_string()]);
        assert_eq!(result_items[0].1, val0.qb64());
        assert_eq!(result_items[1].0, vec!["a".to_string(), "2".to_string()]);
        assert_eq!(result_items[1].1, val1_diger.qb64());

        // Add more data
        let keys_b1: &[&[u8]] = &[b"b".as_ref(), b"1".as_ref()];
        let keys_b2: &[&[u8]] = &[b"b".as_ref(), b"2".as_ref()];
        let keys_bc1: &[&[u8]] = &[b"bc".as_ref(), b"1".as_ref()];

        assert!(sdb_figs.put(keys_b1, &val0)?);
        assert!(sdb_figs.put(keys_b2, &val1_diger)?);
        assert!(sdb_figs.put(keys_bc1, &val0)?);

        // Test with topkey (prefix filtering)
        let top_keys: &[&[u8]] = &[b"b".as_ref(), b"".as_ref()];
        let items = sdb_figs.get_item_iter(top_keys, true)?;
        let processed_items = sdb_figs.process_items(items)?;

        let mut result_items = Vec::new();
        for (keys_vec, val) in processed_items {
            let keys_tuple: Vec<String> = keys_vec.into_iter()
                .map(|k| String::from_utf8(k).unwrap())
                .collect();

            result_items.push((keys_tuple, val.qb64()));
        }

        assert_eq!(result_items.len(), 2);
        assert_eq!(result_items[0].0, vec!["b".to_string(), "1".to_string()]);
        assert_eq!(result_items[0].1, val0.qb64());
        assert_eq!(result_items[1].0, vec!["b".to_string(), "2".to_string()]);
        assert_eq!(result_items[1].1, val1_diger.qb64());

        // Test Siger class
        let db_ref = Arc::new(&lmdber);
        let sdb_siger = CesrSuber::<Siger>::new(db_ref.clone(), "pigs.", None, true).unwrap();

        let sig0 = "AACdI8OSQkMJ9r-xigjEByEjIua7LHH3AOJ22PQKqljMhuhcgh9nGRcKnsz5KvKd7K_H9-1298F4Id1DxvIoEmCQ";
        let val0 = Siger::from_qb64(sig0, None)?;

        let keys: &[&[u8]] = &[b"zeta".as_ref(), b"cat".as_ref()];

        assert!(sdb_siger.put(keys, &val0)?);

        let actual = sdb_siger.get(keys)?.unwrap();
        assert_eq!(actual.qb64(), val0.qb64());

        Ok(())
    }
}