use crate::keri::db::dbing::LMDBer;
use crate::keri::db::subing::{Suber, SuberBase};
use crate::keri::db::subing::{SuberError, Utf8Codec, ValueCodec};
use std::sync::Arc;

pub struct OnSuberBase<'db, C: ValueCodec = Utf8Codec> {
    pub base: SuberBase<'db, C>,
}

impl<'db, C: ValueCodec> crate::keri::db::subing::on::OnSuberBase<'db, C> {
    /// Creates a new `OnSuberBase`.
    ///
    /// # Parameters
    /// * `db` - The base database (LMDBer)
    /// * `subkey` - LMDB sub database key
    /// * `sep` - Separator to convert keys iterator to key bytes for db key. Default '.'
    /// * `verify` - Whether to reverify when ._des from db when applicable. Default false
    /// * `dupsort` - Whether to enable duplicates at each key. Default false
    pub fn new(
        db: Arc<&'db LMDBer>,
        subkey: &str,
        sep: Option<u8>,
        verify: bool,
        dupsort: Option<bool>,
    ) -> Result<Self, SuberError> {
        let base = SuberBase::new(db, subkey, sep, verify, dupsort)?;

        Ok(Self { base })
    }

    /// Returns whether duplicates are enabled at each key
    pub fn is_dupsort(&self) -> bool {
        self.base.is_dupsort()
    }

    /// Converts a collection of keys to a single key byte vector
    pub fn _tokey<K: AsRef<[u8]>>(&self, keys: &[K]) -> Vec<u8> {
        self.base.to_key(keys, false)
    }

    /// Converts a key byte vector to a collection of keys
    pub fn _tokeys(&self, key: &[u8]) -> Vec<Vec<u8>> {
        self.base.to_keys(key)
    }

    /// Serializes a value
    pub fn _ser<T: ?Sized + Clone + Into<Vec<u8>>>(&self, val: &T) -> Result<Vec<u8>, SuberError> {
        self.base.ser(val)
    }

    /// Deserializes a value
    pub fn _des<T: TryFrom<Vec<u8>>>(&self, val: &[u8]) -> Result<T, SuberError> {
        self.base.des(val)
    }

    /// Puts a value at a key with an ordinal number
    ///
    /// # Returns
    /// * `true` if the onkey made from key+sep+serialized on is not found in database so value is written idempotently
    /// * `false` otherwise
    ///
    /// # Parameters
    /// * `keys` - Keys as prefix to be combined with serialized on suffix and sep to form onkey
    /// * `on` - Ordinal number used to form key
    /// * `val` - Serialization
    pub fn put_on<K: AsRef<[u8]>, V: ?Sized + Clone + Into<Vec<u8>>>(
        &self,
        keys: &[K],
        on: u32,
        val: &V,
    ) -> Result<bool, SuberError> {
        let key = self._tokey(keys);
        let sval = self._ser(val)?;

        self.base
            .db
            .put_on_val(&self.base.sdb, &key, on, &sval, Some([self.base.sep]))
            .map_err(SuberError::DBError)
    }

    /// Sets or overwrites a value at a key with an ordinal number
    ///
    /// # Returns
    /// * `true` if value is written or overwritten at onkey
    /// * `false` otherwise
    ///
    /// # Parameters
    /// * `keys` - Keys as prefix to be combined with serialized on suffix and sep to form onkey
    /// * `on` - Ordinal number used to form key
    /// * `val` - Serialization
    pub fn pin_on<K: AsRef<[u8]>, V: ?Sized + Clone + Into<Vec<u8>>>(
        &self,
        keys: &[K],
        on: u32,
        val: &V,
    ) -> Result<bool, SuberError> {
        let key = self._tokey(keys);
        let sval = self._ser(val)?;

        self.base
            .db
            .set_on_val(
                &self.base.sdb,
                &key,
                Some(on as u64),
                &sval,
                Some([self.base.sep]),
            )
            .map_err(SuberError::DBError)
    }

    /// Appends a value with an automatically assigned ordinal number
    ///
    /// # Returns
    /// * Ordinal number of newly appended value
    ///
    /// # Parameters
    /// * `keys` - Top keys as prefix to be combined with serialized on suffix and sep to form key
    /// * `val` - Serialization
    pub fn append_on<K: AsRef<[u8]>, V: ?Sized + Clone + Into<Vec<u8>>>(
        &self,
        keys: &[K],
        val: &V,
    ) -> Result<u64, SuberError> {
        let key = self._tokey(keys);
        let sval = self._ser(val)?;

        self.base
            .db
            .append_on_val(&self.base.sdb, &key, &sval, Some([self.base.sep]))
            .map_err(SuberError::DBError)
    }

    /// Gets a value at a key with an ordinal number
    ///
    /// # Returns
    /// * Serialization at onkey if any
    /// * None if no entry at onkey
    ///
    /// # Parameters
    /// * `keys` - Keys as prefix to be combined with serialized on suffix and sep to form onkey
    /// * `on` - Ordinal number used to form key
    pub fn get_on<K: AsRef<[u8]>, R: TryFrom<Vec<u8>>>(
        &self,
        keys: &[K],
        on: u32,
    ) -> Result<Option<R>, SuberError>
    where
        <R as TryFrom<Vec<u8>>>::Error: std::fmt::Debug,
    {
        let key = self._tokey(keys);

        match self
            .base
            .db
            .get_on_val(&self.base.sdb, &key, on, Some([self.base.sep]))
            .map_err(SuberError::DBError)?
        {
            Some(val) => Ok(Some(self._des(&val)?)),
            None => Ok(None),
        }
    }

    /// Removes a value at a key with an ordinal number
    ///
    /// # Returns
    /// * `true` if onkey made from key+sep+serialized on is found in database so value is removed
    /// * `false` otherwise
    ///
    /// # Parameters
    /// * `keys` - Keys as prefix to be combined with serialized on suffix and sep to form onkey
    /// * `on` - Ordinal number used to form key
    pub fn rem_on<K: AsRef<[u8]>>(&self, keys: &[K], on: u32) -> Result<bool, SuberError> {
        let key = self._tokey(keys);

        self.base
            .db
            .del_on_val(&self.base.sdb, &key, on, Some([self.base.sep]))
            .map_err(SuberError::DBError)
    }

    /// Counts the number of values with ordinal number suffix
    ///
    /// # Returns
    /// * Count of all ordinal suffix keyed vals with same key prefix but different on in onkey
    ///
    /// # Parameters
    /// * `keys` - Top keys as prefix to be combined with serialized on suffix and sep to form top key
    /// * `on` - Ordinal number used to form key
    pub fn cnt_on<K: AsRef<[u8]>>(&self, keys: &[K], on: u32) -> Result<usize, SuberError> {
        let key = self._tokey(keys);

        self.base
            .db
            .cnt_on_vals(
                &self.base.sdb,
                Some(&key),
                Some(on as u64),
                Some([self.base.sep]),
            )
            .map_err(SuberError::DBError)
    }

    /// Gets an iterator over values with ordinal number suffix >= on
    ///
    /// # Returns
    /// * Iterator over values with same key but increments of on >= on
    ///
    /// # Parameters
    /// * `keys` - Keys as prefix to be combined with serialized on suffix and sep to form actual key
    /// * `on` - Ordinal number used to form key at which to initiate retrieval
    pub fn get_on_iter<K: AsRef<[u8]>, R: TryFrom<Vec<u8>> + 'static>(
        &self,
        keys: &[K],
        on: u32,
    ) -> Result<Vec<R>, SuberError>
    where
        <R as TryFrom<Vec<u8>>>::Error: std::fmt::Debug,
    {
        let key = self._tokey(keys);
        let mut raw_results: Vec<Vec<u8>> = Vec::new(); // First collect raw bytes

        self.base
            .db
            .get_on_val_iter(
                &self.base.sdb,
                Some(&key),
                Some(on as u64),
                Some([self.base.sep]),
                |val| {
                    // Store the value to process after the callback
                    raw_results.push(val.to_vec());
                    Ok(true)
                },
            )
            .map_err(SuberError::DBError)?;

        // Process the values after the callback is done
        let mut results = Vec::new(); // This will hold the final deserialized values
        for val in raw_results {
            results.push(self._des(&val)?);
        }

        Ok(results)
    }

    /// Gets an iterator over (key, on, val) triples with ordinal number suffix >= on
    ///
    /// # Returns
    /// * Iterator over (key, on, val) triples with same key but increments of on >= on
    ///
    /// # Parameters
    /// * `keys` - Keys as prefix to be combined with serialized on suffix and sep to form actual key
    /// * `on` - Ordinal number used to form key at which to initiate retrieval
    pub fn get_on_item_iter<K: AsRef<[u8]>, R: TryFrom<Vec<u8>> + 'static>(
        &self,
        keys: &[K],
        on: u32,
    ) -> Result<Vec<(Vec<Vec<u8>>, u64, R)>, SuberError>
    where
        <R as TryFrom<Vec<u8>>>::Error: std::fmt::Debug,
    {
        let key = self._tokey(keys);
        let mut raw_results: Vec<(Vec<u8>, u64, Vec<u8>)> = Vec::new();

        self.base
            .db
            .get_on_item_iter(
                &self.base.sdb,
                Some(&key),
                Some(on as u64),
                Some([self.base.sep]),
                |k, o, val| {
                    // Store the data to process after the callback
                    let k_copy = k.to_vec();
                    let val_copy = val.to_vec();
                    raw_results.push((k_copy, o, val_copy));
                    Ok(true)
                },
            )
            .map_err(SuberError::DBError)?;

        // Process the data after the callback is done
        let mut results = Vec::new();
        for (k, o, val) in raw_results {
            let deserialized = self._des(&val)?;
            results.push((self._tokeys(&k), o, deserialized));
        }

        Ok(results)
    }
}

pub struct OnSuber<'db, C: ValueCodec = Utf8Codec> {
    pub base: Suber<'db, C>,
    pub on_base: OnSuberBase<'db, C>,
}

impl<'db, C: ValueCodec> OnSuber<'db, C> {
    pub fn new(
        db: Arc<&'db LMDBer>,
        subkey: &str,
        sep: Option<u8>,
        verify: bool,
    ) -> Result<Self, SuberError> {
        let base = Suber::new(db.clone(), subkey, sep, verify)?;
        let on_base = OnSuberBase::new(db, subkey, sep, verify, Some(false))?;

        Ok(Self { base, on_base })
    }

    // === Methods from Suber ===

    pub fn put<K: AsRef<[u8]>, V: ?Sized + Clone + Into<Vec<u8>>>(
        &self,
        keys: &[K],
        val: &V,
    ) -> Result<bool, SuberError> {
        self.base.put(keys, val)
    }

    pub fn pin<K: AsRef<[u8]>, V: ?Sized + Clone + Into<Vec<u8>>>(
        &self,
        keys: &[K],
        val: &V,
    ) -> Result<bool, SuberError> {
        self.base.pin(keys, val)
    }

    pub fn get<K: AsRef<[u8]>, V: TryFrom<Vec<u8>>>(
        &self,
        keys: &[K],
    ) -> Result<Option<V>, SuberError> {
        self.base.get(keys)
    }

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

    pub fn get_item_iter<K: AsRef<[u8]>>(
        &self,
        keys: &[K],
        topive: bool,
    ) -> Result<Vec<(Vec<Vec<u8>>, Vec<u8>)>, SuberError> {
        self.base.get_item_iter(keys, topive)
    }

    pub fn cnt_all(&self) -> Result<usize, SuberError> {
        self.base.cnt_all()
    }

    // === Methods from OnSuberBase ===

    pub fn is_dupsort(&self) -> bool {
        self.on_base.is_dupsort()
    }

    pub fn put_on<K: AsRef<[u8]>, V: ?Sized + Clone + Into<Vec<u8>>>(
        &self,
        keys: &[K],
        on: u32,
        val: &V,
    ) -> Result<bool, SuberError> {
        self.on_base.put_on(keys, on, val)
    }

    pub fn pin_on<K: AsRef<[u8]>, V: ?Sized + Clone + Into<Vec<u8>>>(
        &self,
        keys: &[K],
        on: u32,
        val: &V,
    ) -> Result<bool, SuberError> {
        self.on_base.pin_on(keys, on, val)
    }

    pub fn append_on<K: AsRef<[u8]>, V: ?Sized + Clone + Into<Vec<u8>>>(
        &self,
        keys: &[K],
        val: &V,
    ) -> Result<u64, SuberError> {
        self.on_base.append_on(keys, val)
    }

    pub fn get_on<K: AsRef<[u8]>, R: TryFrom<Vec<u8>>>(
        &self,
        keys: &[K],
        on: u32,
    ) -> Result<Option<R>, SuberError>
    where
        <R as TryFrom<Vec<u8>>>::Error: std::fmt::Debug,
    {
        self.on_base.get_on(keys, on)
    }

    pub fn rem_on<K: AsRef<[u8]>>(&self, keys: &[K], on: u32) -> Result<bool, SuberError> {
        self.on_base.rem_on(keys, on)
    }

    pub fn cnt_on<K: AsRef<[u8]>>(&self, keys: &[K], on: u32) -> Result<usize, SuberError> {
        self.on_base.cnt_on(keys, on)
    }

    pub fn get_on_iter<K: AsRef<[u8]>, R: TryFrom<Vec<u8>> + 'static>(
        &self,
        keys: &[K],
        on: u32,
    ) -> Result<Vec<R>, SuberError>
    where
        <R as TryFrom<Vec<u8>>>::Error: std::fmt::Debug,
    {
        self.on_base.get_on_iter(keys, on)
    }

    pub fn get_on_item_iter<K: AsRef<[u8]>, R: TryFrom<Vec<u8>> + 'static>(
        &self,
        keys: &[K],
        on: u32,
    ) -> Result<Vec<(Vec<Vec<u8>>, u64, R)>, SuberError>
    where
        <R as TryFrom<Vec<u8>>>::Error: std::fmt::Debug,
    {
        self.on_base.get_on_item_iter(keys, on)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keri::db::dbing::LMDBer;
    use std::sync::Arc;

    #[test]
    fn test_on_suber() -> Result<(), SuberError> {
        // Create a temporary database
        let db = LMDBer::builder()
            .temp(true)
            .name("test")
            .build()
            .map_err(SuberError::DBError)?;

        assert_eq!(db.name(), "test");
        assert!(db.opened());

        let db_ref = Arc::new(&db);

        // Create OnSuber instance
        let onsuber = OnSuber::<Utf8Codec>::new(db_ref, "bags.", None, false)?;

        // Verify not dupsort (matches Python test)
        assert!(!onsuber.is_dupsort());

        // Test values
        let w = "Blue dog";
        let x = "Green tree";
        let y = "Red apple";
        let z = "White snow";

        // Test append_on
        assert_eq!(onsuber.append_on(&["a"], &w)?, 0);
        assert_eq!(onsuber.append_on(&["a"], &x)?, 1);
        assert_eq!(onsuber.append_on(&["a"], &y)?, 2);
        assert_eq!(onsuber.append_on(&["a"], &z)?, 3);

        // Test cnt_on
        assert_eq!(onsuber.cnt_on(&["a"], 0)?, 4);
        assert_eq!(onsuber.cnt_on(&["a"], 2)?, 2);
        assert_eq!(onsuber.cnt_on(&["a"], 4)?, 0);

        // Test get_item_iter
        let items: Vec<(Vec<Vec<u8>>, Vec<u8>)> = onsuber.get_item_iter(&[] as &[&str], true)?;

        // Convert to strings for easier assertions
        let items_as_strings: Vec<(Vec<String>, String)> = items
            .into_iter()
            .map(|(keys_bytes, val_bytes)| {
                let parsed_keys = keys_bytes
                    .into_iter()
                    .map(|k| String::from_utf8(k).unwrap())
                    .collect();
                (parsed_keys, String::from_utf8(val_bytes).unwrap())
            })
            .collect();

        assert_eq!(items_as_strings.len(), 4);
        assert!(items_as_strings.contains(&(
            vec![
                "a".to_string(),
                "00000000000000000000000000000000".to_string()
            ],
            "Blue dog".to_string()
        )));
        assert!(items_as_strings.contains(&(
            vec![
                "a".to_string(),
                "00000000000000000000000000000001".to_string()
            ],
            "Green tree".to_string()
        )));
        assert!(items_as_strings.contains(&(
            vec![
                "a".to_string(),
                "00000000000000000000000000000002".to_string()
            ],
            "Red apple".to_string()
        )));
        assert!(items_as_strings.contains(&(
            vec![
                "a".to_string(),
                "00000000000000000000000000000003".to_string()
            ],
            "White snow".to_string()
        )));

        // Test get_on_item_iter
        let on_items: Vec<(Vec<Vec<u8>>, u64, Vec<u8>)> =
            onsuber.get_on_item_iter::<&str, Vec<u8>>(&[] as &[&str], 0)?;

        // Convert to strings for easier assertions
        let on_items_as_strings: Vec<(Vec<String>, u64, String)> = on_items
            .into_iter()
            .map(|(keys_bytes, idx, val_bytes)| {
                let parsed_keys = keys_bytes
                    .into_iter()
                    .map(|k| String::from_utf8(k).unwrap())
                    .collect();
                (parsed_keys, idx, String::from_utf8(val_bytes).unwrap())
            })
            .collect();

        assert_eq!(on_items_as_strings.len(), 4);
        assert!(on_items_as_strings.contains(&(vec!["a".to_string()], 0, "Blue dog".to_string())));
        assert!(on_items_as_strings.contains(&(
            vec!["a".to_string()],
            1,
            "Green tree".to_string()
        )));
        assert!(on_items_as_strings.contains(&(vec!["a".to_string()], 2, "Red apple".to_string())));
        assert!(on_items_as_strings.contains(&(
            vec!["a".to_string()],
            3,
            "White snow".to_string()
        )));

        // Test get_on_item_iter with specific key
        let on_items: Vec<(Vec<Vec<u8>>, u64, Vec<u8>)> = onsuber.get_on_item_iter(&["a"], 0)?;

        // Convert to strings
        let on_items_as_strings: Vec<(Vec<String>, u64, String)> = on_items
            .into_iter()
            .map(|(keys_bytes, idx, val_bytes)| {
                let parsed_keys = keys_bytes
                    .into_iter()
                    .map(|k| String::from_utf8(k).unwrap())
                    .collect();
                (parsed_keys, idx, String::from_utf8(val_bytes).unwrap())
            })
            .collect();

        assert_eq!(on_items_as_strings.len(), 4);
        assert!(on_items_as_strings.contains(&(vec!["a".to_string()], 0, "Blue dog".to_string())));
        assert!(on_items_as_strings.contains(&(
            vec!["a".to_string()],
            1,
            "Green tree".to_string()
        )));
        assert!(on_items_as_strings.contains(&(vec!["a".to_string()], 2, "Red apple".to_string())));
        assert!(on_items_as_strings.contains(&(
            vec!["a".to_string()],
            3,
            "White snow".to_string()
        )));

        // Test get_on_item_iter with specific on index
        let on_items: Vec<(Vec<Vec<u8>>, u64, Vec<u8>)> = onsuber.get_on_item_iter(&["a"], 2)?;

        // Convert to strings
        let on_items_as_strings: Vec<(Vec<String>, u64, String)> = on_items
            .into_iter()
            .map(|(keys_bytes, idx, val_bytes)| {
                let parsed_keys = keys_bytes
                    .into_iter()
                    .map(|k| String::from_utf8(k).unwrap())
                    .collect();
                (parsed_keys, idx, String::from_utf8(val_bytes).unwrap())
            })
            .collect();

        assert_eq!(on_items_as_strings.len(), 2);
        assert!(on_items_as_strings.contains(&(vec!["a".to_string()], 2, "Red apple".to_string())));
        assert!(on_items_as_strings.contains(&(
            vec!["a".to_string()],
            3,
            "White snow".to_string()
        )));

        // Test get_on_iter - no args
        let on_vals: Vec<Vec<u8>> = onsuber.get_on_iter::<&str, Vec<u8>>(&[] as &[&str], 0)?;

        // Convert to strings
        let on_vals_as_strings: Vec<String> = on_vals
            .into_iter()
            .map(|val| String::from_utf8(val).unwrap())
            .collect();

        assert_eq!(on_vals_as_strings.len(), 4);
        assert!(on_vals_as_strings.contains(&"Blue dog".to_string()));
        assert!(on_vals_as_strings.contains(&"Green tree".to_string()));
        assert!(on_vals_as_strings.contains(&"Red apple".to_string()));
        assert!(on_vals_as_strings.contains(&"White snow".to_string()));

        // Test get_on_iter with specific key
        let on_vals: Vec<Vec<u8>> = onsuber.get_on_iter(&["a"], 0)?;

        // Convert to strings
        let on_vals_as_strings: Vec<String> = on_vals
            .into_iter()
            .map(|val| String::from_utf8(val).unwrap())
            .collect();

        assert_eq!(on_vals_as_strings.len(), 4);
        assert!(on_vals_as_strings.contains(&"Blue dog".to_string()));
        assert!(on_vals_as_strings.contains(&"Green tree".to_string()));
        assert!(on_vals_as_strings.contains(&"Red apple".to_string()));
        assert!(on_vals_as_strings.contains(&"White snow".to_string()));

        // Test get_on_iter with specific on index
        let on_vals: Vec<Vec<u8>> = onsuber.get_on_iter(&["a"], 2)?;

        // Convert to strings
        let on_vals_as_strings: Vec<String> = on_vals
            .into_iter()
            .map(|val| String::from_utf8(val).unwrap())
            .collect();

        assert_eq!(on_vals_as_strings.len(), 2);
        assert!(on_vals_as_strings.contains(&"Red apple".to_string()));
        assert!(on_vals_as_strings.contains(&"White snow".to_string()));

        // Test append for additional keys
        assert_eq!(onsuber.append_on(&["b"], &w)?, 0);
        assert_eq!(onsuber.append_on(&["b"], &x)?, 1);
        assert_eq!(onsuber.append_on(&["bc"], &y)?, 0);
        assert_eq!(onsuber.append_on(&["ac"], &z)?, 0);

        // Test counts
        assert_eq!(onsuber.cnt_on(&["b"], 0)?, 2);
        assert_eq!(onsuber.cnt_on(&["ac"], 2)?, 0);
        assert_eq!(onsuber.cnt_on(&[""], 0)?, 8);

        // Test get_item_iter for all items
        let items = onsuber.get_item_iter::<Vec<u8>>(&[], true)?;

        // Convert to strings for easier assertions
        let items_as_strings: Vec<(Vec<String>, String)> = items
            .into_iter()
            .map(|(keys_bytes, val_bytes)| {
                let parsed_keys = keys_bytes
                    .into_iter()
                    .map(|k| String::from_utf8(k).unwrap())
                    .collect();
                (parsed_keys, String::from_utf8(val_bytes).unwrap())
            })
            .collect();

        assert_eq!(items_as_strings.len(), 8);
        // Check all the key-value pairs we expect
        assert!(items_as_strings.contains(&(
            vec![
                "a".to_string(),
                "00000000000000000000000000000000".to_string()
            ],
            "Blue dog".to_string()
        )));
        assert!(items_as_strings.contains(&(
            vec![
                "a".to_string(),
                "00000000000000000000000000000001".to_string()
            ],
            "Green tree".to_string()
        )));
        assert!(items_as_strings.contains(&(
            vec![
                "a".to_string(),
                "00000000000000000000000000000002".to_string()
            ],
            "Red apple".to_string()
        )));
        assert!(items_as_strings.contains(&(
            vec![
                "a".to_string(),
                "00000000000000000000000000000003".to_string()
            ],
            "White snow".to_string()
        )));
        assert!(items_as_strings.contains(&(
            vec![
                "ac".to_string(),
                "00000000000000000000000000000000".to_string()
            ],
            "White snow".to_string()
        )));
        assert!(items_as_strings.contains(&(
            vec![
                "b".to_string(),
                "00000000000000000000000000000000".to_string()
            ],
            "Blue dog".to_string()
        )));
        assert!(items_as_strings.contains(&(
            vec![
                "b".to_string(),
                "00000000000000000000000000000001".to_string()
            ],
            "Green tree".to_string()
        )));
        assert!(items_as_strings.contains(&(
            vec![
                "bc".to_string(),
                "00000000000000000000000000000000".to_string()
            ],
            "Red apple".to_string()
        )));

        // Test get_on_item_iter with specific key
        let on_items: Vec<(Vec<Vec<u8>>, u64, Vec<u8>)> = onsuber.get_on_item_iter(&["b"], 0)?;

        // Convert to strings
        let on_items_as_strings: Vec<(Vec<String>, u64, String)> = on_items
            .into_iter()
            .map(|(keys_bytes, idx, val_bytes)| {
                let parsed_keys = keys_bytes
                    .into_iter()
                    .map(|k| String::from_utf8(k).unwrap())
                    .collect();
                (parsed_keys, idx, String::from_utf8(val_bytes).unwrap())
            })
            .collect();

        assert_eq!(on_items_as_strings.len(), 2);
        assert!(on_items_as_strings.contains(&(vec!["b".to_string()], 0, "Blue dog".to_string())));
        assert!(on_items_as_strings.contains(&(
            vec!["b".to_string()],
            1,
            "Green tree".to_string()
        )));

        // Test get_on_item_iter with tuple key
        let on_items: Vec<(Vec<Vec<u8>>, u64, Vec<u8>)> = onsuber.get_on_item_iter(&["b"], 0)?;

        // Convert to strings
        let on_items_as_strings: Vec<(Vec<String>, u64, String)> = on_items
            .into_iter()
            .map(|(keys_bytes, idx, val_bytes)| {
                let parsed_keys = keys_bytes
                    .into_iter()
                    .map(|k| String::from_utf8(k).unwrap())
                    .collect();
                (parsed_keys, idx, String::from_utf8(val_bytes).unwrap())
            })
            .collect();

        assert_eq!(on_items_as_strings.len(), 2);
        assert!(on_items_as_strings.contains(&(vec!["b".to_string()], 0, "Blue dog".to_string())));
        assert!(on_items_as_strings.contains(&(
            vec!["b".to_string()],
            1,
            "Green tree".to_string()
        )));

        // Test get_on_item_iter with empty key parts
        let on_items: Vec<(Vec<Vec<u8>>, u64, Vec<u8>)> =
            onsuber.get_on_item_iter(&["b", ""], 0)?;
        assert_eq!(on_items.len(), 0);

        // Test get_on_item_iter with empty key
        let on_items: Vec<(Vec<Vec<u8>>, u64, Vec<u8>)> = onsuber.get_on_item_iter(&[""], 0)?;

        // Convert to strings
        let on_items_as_strings: Vec<(Vec<String>, u64, String)> = on_items
            .into_iter()
            .map(|(keys_bytes, idx, val_bytes)| {
                let parsed_keys = keys_bytes
                    .into_iter()
                    .map(|k| String::from_utf8(k).unwrap())
                    .collect();
                (parsed_keys, idx, String::from_utf8(val_bytes).unwrap())
            })
            .collect();

        assert_eq!(on_items_as_strings.len(), 8);
        // Here we'd check all 8 items but for brevity I'll check just the count

        // Test get_on_item_iter with no args
        let on_items: Vec<(Vec<Vec<u8>>, u64, Vec<u8>)> =
            onsuber.get_on_item_iter::<&str, Vec<u8>>(&[], 0)?;

        // Convert to strings
        let on_items_as_strings: Vec<(Vec<String>, u64, String)> = on_items
            .into_iter()
            .map(|(keys_bytes, idx, val_bytes)| {
                let parsed_keys = keys_bytes
                    .into_iter()
                    .map(|k| String::from_utf8(k).unwrap())
                    .collect();
                (parsed_keys, idx, String::from_utf8(val_bytes).unwrap())
            })
            .collect();

        assert_eq!(on_items_as_strings.len(), 8);
        // Again, just checking count for brevity

        // Test rem_on
        assert!(onsuber.rem_on(&["a"], 1)?);
        assert!(!onsuber.rem_on(&["a"], 1)?); // Should now return false as already removed
        assert!(onsuber.rem_on(&["a"], 3)?);
        assert!(!onsuber.rem_on(&["a"], 3)?); // Should now return false as already removed

        // Verify count after removal
        assert_eq!(onsuber.cnt_on(&["a"], 0)?, 2);

        // Test get_on_item_iter after removals
        let on_items: Vec<(Vec<Vec<u8>>, u64, Vec<u8>)> = onsuber.get_on_item_iter(&["a"], 0)?;

        // Convert to strings
        let on_items_as_strings: Vec<(Vec<String>, u64, String)> = on_items
            .into_iter()
            .map(|(keys_bytes, idx, val_bytes)| {
                let parsed_keys = keys_bytes
                    .into_iter()
                    .map(|k| String::from_utf8(k).unwrap())
                    .collect();
                (parsed_keys, idx, String::from_utf8(val_bytes).unwrap())
            })
            .collect();

        assert_eq!(on_items_as_strings.len(), 2);
        assert!(on_items_as_strings.contains(&(vec!["a".to_string()], 0, "Blue dog".to_string())));
        assert!(on_items_as_strings.contains(&(vec!["a".to_string()], 2, "Red apple".to_string())));

        // Test put_on and get_on
        assert!(onsuber.put_on(&["d"], 0, &"moon")?);
        let moon: Option<Vec<u8>> = onsuber.get_on(&["d"], 0)?;
        assert!(moon.is_some());
        assert_eq!(String::from_utf8(moon.unwrap()).unwrap(), "moon");

        // Test put_on with duplicate (should return false)
        assert!(!onsuber.put_on(&["d"], 0, &"moon")?);

        // Test pin_on
        assert!(onsuber.pin_on(&["d"], 0, &"sun")?);
        let sun: Option<Vec<u8>> = onsuber.get_on(&["d"], 0)?;
        assert!(sun.is_some());
        assert_eq!(String::from_utf8(sun.unwrap()).unwrap(), "sun");

        // Test rem_on
        assert!(onsuber.rem_on(&["d"], 0)?);

        // The database should be closed when db goes out of scope
        drop(db);

        Ok(())
    }
}
