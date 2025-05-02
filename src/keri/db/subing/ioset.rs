use crate::keri::db::dbing::LMDBer;
use crate::keri::db::errors::DBError;
use crate::keri::db::subing::{SuberBase, SuberError, Utf8Codec, ValueCodec};
use std::sync::Arc;

/// Represents an Insertion Ordered Set Suber.

pub struct IoSetSuber<'db, C: ValueCodec = Utf8Codec> {
    base: SuberBase<'db, C>,
}

impl<'db, C: ValueCodec> IoSetSuber<'db, C> {
    /// Creates a new `IoSetSuber`.
    pub fn new(
        db: Arc<&'db LMDBer>,
        subkey: &str,
        sep: Option<u8>,
        verify: bool,
    ) -> Result<Self, SuberError> {
        let base = SuberBase::new(db, subkey, sep, verify, Some(false))?;
        Ok(Self { base })
    }

    /// Puts multiple values into the set associated with the given keys.
    ///
    /// Adds only values that are not already present in the set for the effective key.
    /// Does not overwrite existing identical values. Values are appended in insertion order.
    ///
    /// # Arguments
    ///
    /// * `keys`: An array slice of key parts.
    /// * `vals`: An array slice of values to put.
    ///
    /// # Returns
    ///
    /// `Ok(true)` if the operation was successful (note: underlying LMDB operation might always return true here).
    /// `Ok(false)` if the operation failed at the LMDB level.
    /// Returns `Err(SuberError)` on key/value processing or database errors.
    pub fn put<K: AsRef<[u8]>, V: ?Sized + Clone + Into<Vec<u8>>>(
        &self,
        keys: &[K],
        vals: &[&V],
    ) -> Result<bool, SuberError> {
        let key = self.base.to_key(keys, false);

        // 1. Serialize into owned Vec<Vec<u8>> and handle potential error
        let serialized_vals: Vec<Vec<u8>> = vals
            .iter()
            .map(|v| self.base.ser(*v))
            .collect::<Result<Vec<Vec<u8>>, _>>()?; // Use turbofish for clarity and collect the Result

        // 2. Create Vec<&[u8]> by borrowing from the now longer-lived 'serialized_vals'
        let val_slices: Vec<&[u8]> = serialized_vals
            .iter() // Borrow serialized_vals
            .map(|v| v.as_slice()) // Create slices borrowing from elements of serialized_vals
            .collect();

        // 3. Use the Vec<&[u8]>
        self.base
            .db
            .put_io_set_vals(&self.base.sdb, &key, &val_slices, Some([self.base.sep]))
            .map_err(SuberError::DBError)
    }

    /// Adds a single value idempotently to the set associated with the given keys.
    ///
    /// If the value already exists in the set for the effective key, it is not added again.
    ///
    /// # Arguments
    ///
    /// * `keys`: An array slice of key parts.
    /// * `val`: The value to add.
    ///
    /// # Returns
    ///
    /// `Ok(true)` if the value was added (i.e., it was not already present).
    /// `Ok(false)` if the value was already present.
    /// Returns `Err(SuberError)` on key/value processing or database errors.
    pub fn add<K: AsRef<[u8]>, V: ?Sized + Clone + Into<Vec<u8>>>(
        &self,
        keys: &[K],
        val: &V,
    ) -> Result<bool, SuberError> {
        let key = self.base.to_key(keys, false);
        let sval = self.base.ser(val)?;
        self.base
            .db
            .add_io_set_val(&self.base.sdb, &key, &sval, Some([self.base.sep]))
            .map_err(SuberError::DBError)
    }

    /// Pins (sets/replaces) the values associated with the given keys.
    ///
    /// Removes all pre-existing values for the effective key and replaces them with the provided `vals`.
    ///
    /// # Arguments
    ///
    /// * `keys`: An array slice of key parts.
    /// * `vals`: An array slice of the new values to set.
    ///
    /// # Returns
    ///
    /// `Ok(true)` if the operation was successful.
    /// `Ok(false)` if the operation failed at the LMDB level.
    /// Returns `Err(SuberError)` on key/value processing or database errors.
    /// Pins (sets/replaces) the values associated with the given keys.
    ///
    /// Removes all pre-existing values for the effective key and replaces them with the provided `vals`.
    /// Each value is serialized using the configured ValueCodec before storage.
    ///
    /// # Arguments
    ///
    /// * `keys`: An array slice of key parts.
    /// * `vals`: An array slice of the new values to set.
    ///
    /// # Returns
    ///
    /// `Ok(true)` if the operation was successful.
    /// `Ok(false)` if the operation failed at the LMDB level.
    /// Returns `Err(SuberError)` on key/value processing or database errors.
    pub fn pin<K: AsRef<[u8]>, V: ?Sized + Clone + Into<Vec<u8>>>(
        &self,
        keys: &[K],
        vals: &[&V],
    ) -> Result<bool, SuberError> {
        let key = self.base.to_key(keys, false);

        // 1. Serialize into owned Vec<Vec<u8>> and handle potential error
        let serialized_vals: Vec<Vec<u8>> = vals
            .iter()
            .map(|v| self.base.ser(*v))
            .collect::<Result<Vec<Vec<u8>>, _>>()?;

        // 2. Create Vec<&[u8]> by borrowing from the serialized_vals
        let val_slices: Vec<&[u8]> = serialized_vals.iter().map(|v| v.as_slice()).collect();

        // 3. Use the Vec<&[u8]> with the underlying database operation
        self.base
            .db
            .set_io_set_vals(&self.base.sdb, &key, &val_slices, Some([self.base.sep]))
            .map_err(SuberError::DBError)
    }

    /// Gets all values in the set associated with the given keys, in insertion order.
    ///
    /// # Arguments
    ///
    /// * `keys`: An array slice of key parts.
    ///
    /// # Returns
    ///
    /// `Ok(Vec<R>)` containing the deserialized values. Returns an empty Vec if the key doesn't exist.
    /// `Err(SuberError)` on key processing or database/deserialization errors.
    pub fn get<K: AsRef<[u8]>, R: TryFrom<Vec<u8>>>(&self, keys: &[K]) -> Result<Vec<R>, SuberError>
    where
        // Add bound to handle potential errors from TryFrom
        <R as TryFrom<Vec<u8>>>::Error: std::fmt::Debug,
    {
        let key = self.base.to_key(keys, false);
        let raw_vals = self
            .base
            .db
            .get_io_set_vals(&self.base.sdb, &key, None, Some([self.base.sep]))
            .map_err(SuberError::DBError)?;

        raw_vals
            .iter()
            .map(|raw_val| self.base.des(raw_val))
            .collect() // Collects into Result<Vec<R>, SuberError>
    }

    /// Gets an iterator over the values in the set associated with the given keys.
    ///
    /// Values are yielded in insertion order.
    /// Note: This implementation collects into a Vec first due to the underlying callback mechanism.
    /// A true iterator might require a more complex setup or modification to LMDBer.
    ///
    /// # Arguments
    ///
    /// * `keys`: An array slice of key parts.
    ///
    /// # Returns
    ///
    /// `Ok(impl Iterator<Item = Result<R, SuberError>>)` yielding deserialized values.
    /// `Err(SuberError)` on key processing or initial database errors.
    pub fn get_iter<K: AsRef<[u8]>, R: TryFrom<Vec<u8>> + 'static>(
        &self,
        keys: &[K],
    ) -> Result<impl Iterator<Item = Result<R, SuberError>>, SuberError>
    where
        <R as TryFrom<Vec<u8>>>::Error: std::fmt::Debug,
        SuberError: From<<R as TryFrom<Vec<u8>>>::Error>,
    {
        let key = self.base.to_key(keys, false);
        let mut results: Vec<Result<R, SuberError>> = Vec::new();
        let sep = Some([self.base.sep]);

        self.base
            .db
            .get_io_set_vals_iter(&self.base.sdb, &key, None, sep, |val| {
                let result = self.base.des(val);
                results.push(result);
                Ok(true)
            })
            .map_err(SuberError::DBError)?;

        Ok(results.into_iter())
    }

    /// Gets the last value inserted into the set for the given keys.
    ///
    /// # Arguments
    ///
    /// * `keys`: An array slice of key parts.
    ///
    /// # Returns
    ///
    /// `Ok(Some(R))` containing the deserialized last value if found.
    /// `Ok(None)` if the key does not exist or the set is empty.
    /// `Err(SuberError)` on key processing or database/deserialization errors.
    pub fn get_last<K: AsRef<[u8]>, R: TryFrom<Vec<u8>>>(
        &self,
        keys: &[K],
    ) -> Result<Option<R>, SuberError>
    where
        <R as TryFrom<Vec<u8>>>::Error: std::fmt::Debug,
    {
        let key = self.base.to_key(keys, false);
        let raw_val_opt = self
            .base
            .db
            .get_io_set_val_last(&self.base.sdb, &key, Some([self.base.sep]))
            .map_err(SuberError::DBError)?;

        match raw_val_opt {
            Some(raw_val) => self.base.des(&raw_val).map(Some),
            None => Ok(None),
        }
    }

    /// Removes entries associated with the given keys.
    ///
    /// If `val` is `Some`, removes the specific value from the set if it exists.
    /// If `val` is `None`, removes *all* values associated with the effective key.
    ///
    /// # Arguments
    ///
    /// * `keys`: An array slice of key parts.
    /// * `val`: An `Option` containing the specific value to remove, or `None` to remove all.
    ///
    /// # Returns
    ///
    /// `Ok(true)` if the specified value or the entire key entry was found and removed.
    /// `Ok(false)` if the specified value or key was not found.
    /// `Err(SuberError)` on key/value processing or database errors.
    pub fn rem<K: AsRef<[u8]>, V: ?Sized + Clone + Into<Vec<u8>>>(
        &self,
        keys: &[K],
        val: Option<&V>,
    ) -> Result<bool, SuberError> {
        let key = self.base.to_key(keys, false);
        let sep = Some([self.base.sep]);
        match val {
            Some(v) => {
                let sval = self.base.ser(v)?;
                self.base
                    .db
                    .del_io_set_val(&self.base.sdb, &key, &sval, sep)
                    .map_err(SuberError::DBError)
            }
            None => self
                .base
                .db
                .del_io_set_vals(&self.base.sdb, &key, sep)
                .map_err(SuberError::DBError),
        }
    }

    /// Counts the number of values in the set associated with the given keys.
    ///
    /// # Arguments
    ///
    /// * `keys`: An array slice of key parts.
    ///
    /// # Returns
    ///
    /// `Ok(usize)` containing the count of values (0 if the key doesn't exist).
    /// `Err(SuberError)` on key processing or database errors.
    pub fn cnt<K: AsRef<[u8]>>(&self, keys: &[K]) -> Result<usize, SuberError> {
        let key = self.base.to_key(keys, false);
        self.base
            .db
            .cnt_io_set_vals(&self.base.sdb, &key, Some([self.base.sep]))
            .map_err(SuberError::DBError)
    }

    /// Returns an iterator over (keys, value) items whose effective key starts with the prefix derived from `keys`.
    ///
    /// Note: Similar to `get_iter`, this collects results first due to the callback mechanism.
    /// The keys returned in the tuple are split based on the separator.
    ///
    /// # Arguments
    ///
    /// * `keys`: An array slice of key parts forming the prefix.
    /// * `topive`: If true, treat `keys` as a partial prefix (appends separator).
    ///
    /// # Returns
    ///
    /// `Ok(Vec<(Vec<Vec<u8>>, R)>)` containing tuples of (split key parts, deserialized value).
    /// `Err(SuberError)` on key processing or database/deserialization errors.
    pub fn get_item_iter<K: AsRef<[u8]>, R: TryFrom<Vec<u8>>>(
        &self,
        keys: &[K],
        topive: bool,
    ) -> Result<Vec<(Vec<Vec<u8>>, R)>, SuberError>
    where
        <R as TryFrom<Vec<u8>>>::Error: std::fmt::Debug,
        // Ensure DBError can be converted into SuberError
        SuberError: From<DBError>,
    {
        let key_prefix = self.base.to_key(keys, topive);
        let mut raw_items = Vec::new(); // Collect raw key-value pairs first
        let sep = Some([self.base.sep]);

        // --- Stage 1: Iterate and collect raw bytes, handling DBError ---
        self.base
            .db
            .get_top_io_set_items_iter(&self.base.sdb, &key_prefix, sep, |k, v| {
                // k should have the ordinal suffix removed by the LMDBer method
                // Collect raw bytes, don't deserialize yet.
                raw_items.push((k.to_vec(), v.to_vec()));
                Ok(true) // Continue iteration, return type is Result<bool, DBError>
            })?; // Use ? here: If DB iteration fails, convert DBError to SuberError and return

        // --- Stage 2: Process collected raw items, handling SuberError ---
        let mut results = Vec::with_capacity(raw_items.len());
        for (raw_key, raw_val) in raw_items {
            let item_keys = self.base.to_keys(&raw_key); // Split the effective key
            let item_val = self.base.des(&raw_val)?; // Deserialize value. ? now works because we're in the main function scope expecting SuberError.
            results.push((item_keys, item_val));
        }

        Ok(results)
    }

    /// Returns an iterator over all the items including all raw items for all keys
    /// in top branch defined by keys where keys may be truncation of full branch.
    /// Returns full raw values with ordinal suffixes.
    ///
    /// # Arguments
    /// * `keys` - Slice of key parts, potentially a partial key
    /// * `topive` - If true, treat as partial key tuple ending with separator
    ///
    /// # Returns
    /// * `Result<Vec<(Vec<Vec<u8>>, Vec<u8>)>, SuberError>` - Vector of key-value pairs with raw values
    pub fn get_full_item_iter<K: AsRef<[u8]>>(
        &self,
        keys: &[K],
        topive: bool,
    ) -> Result<Vec<(Vec<Vec<u8>>, Vec<u8>)>, SuberError> {
        self.base.get_full_item_iter(keys, topive)
    }

    /// Removes all entries at keys that are in top branch with key prefix matching
    /// keys where keys may be truncation of full branch.
    ///
    /// # Arguments
    /// * `keys` - Slice of key parts, potentially a partial key
    /// * `topive` - If true, treat as partial key tuple ending with separator
    ///
    /// # Returns
    /// * `Result<bool, SuberError>` - True if successful
    pub fn trim<K: AsRef<[u8]>>(&self, keys: &[K], topive: bool) -> Result<bool, SuberError> {
        self.base.trim(keys, topive)
    }
}

mod tests {
    use crate::keri::db::dbing::{LMDBer, LMDBerBuilder};
    use crate::keri::db::subing::ioset::IoSetSuber;
    use crate::keri::db::subing::{SuberError, Utf8Codec};
    use std::sync::Arc;
    use tempfile::tempdir;

    #[test]
    fn test_ioset_suber() -> Result<(), SuberError> {
        // Create a tempdir to ensure test isolation
        let temp_dir = tempdir().unwrap();
        let _dir_path = temp_dir.path().to_path_buf();

        // Open a test database
        let db = LMDBerBuilder::default()
            .name("test")
            .temp(true)
            .build()
            .unwrap();

        assert_eq!(db.name(), "test");
        assert!(db.opened());

        // Create IoSetSuber
        let db_ref = Arc::new(&db);
        let iosuber = IoSetSuber::<Utf8Codec>::new(db_ref, "bags.", None, false)?;

        let sue = "Hello sailer!";
        let sal = "Not my type.";
        let sam = "A real charmer!";
        let zoe = "See ya later.";
        let zia = "Hey gorgeous!";
        let bob = "Shove off!";
        let bil = "Go away.";

        let keys0 = &["test_key", "0001"];
        let keys1 = &["test_key", "0002"];
        let keys2 = &["keystr"];

        // Test put and get
        assert!(iosuber.put(keys0, &[&sal, &sue])?);
        let bytes: Vec<Vec<u8>> = iosuber.get(keys0)?;
        assert_eq!(bytes.len(), 2);
        assert_eq!(String::from_utf8(bytes[0].clone()).unwrap(), sal);
        assert_eq!(String::from_utf8(bytes[1].clone()).unwrap(), sue);
        assert_eq!(iosuber.cnt(keys0)?, 2);

        // Test getLast - manual conversion
        let last_bytes = iosuber.get_last(keys0)?;
        assert!(last_bytes.is_some());
        assert_eq!(String::from_utf8(last_bytes.unwrap()).unwrap(), sue);

        // Test rem
        assert!(iosuber.rem(keys0, None::<&String>)?);
        let bytes: Vec<Vec<u8>> = iosuber.get(keys0)?;
        assert!(bytes.is_empty());
        assert_eq!(iosuber.cnt(keys0)?, 0);

        // Test put again with different order
        assert!(iosuber.put(keys0, &[&sue, &sal])?);
        let bytes: Vec<Vec<u8>> = iosuber.get(keys0)?;
        assert_eq!(bytes.len(), 2);
        assert_eq!(String::from_utf8(bytes[0].clone()).unwrap(), sue);
        assert_eq!(String::from_utf8(bytes[1].clone()).unwrap(), sal);

        // Test getLast again
        let last_bytes = iosuber.get_last(keys0)?;
        assert!(last_bytes.is_some());
        assert_eq!(String::from_utf8(last_bytes.unwrap()).unwrap(), sal);

        // Test add
        assert!(iosuber.add(keys0, &sam)?);
        let bytes: Vec<Vec<u8>> = iosuber.get(keys0)?;
        assert_eq!(bytes.len(), 3);
        assert_eq!(String::from_utf8(bytes[0].clone()).unwrap(), sue);
        assert_eq!(String::from_utf8(bytes[1].clone()).unwrap(), sal);
        assert_eq!(String::from_utf8(bytes[2].clone()).unwrap(), sam);

        // Test pin
        assert!(iosuber.pin(keys0, &[&zoe, &zia])?);
        let bytes: Vec<Vec<u8>> = iosuber.get(keys0)?;
        assert_eq!(bytes.len(), 2);
        assert_eq!(String::from_utf8(bytes[0].clone()).unwrap(), zoe);
        assert_eq!(String::from_utf8(bytes[1].clone()).unwrap(), zia);

        // Test put on a different key
        assert!(iosuber.put(keys1, &[&sal, &sue, &sam])?);
        let bytes: Vec<Vec<u8>> = iosuber.get(keys1)?;
        assert_eq!(bytes.len(), 3);
        assert_eq!(String::from_utf8(bytes[0].clone()).unwrap(), sal);
        assert_eq!(String::from_utf8(bytes[1].clone()).unwrap(), sue);
        assert_eq!(String::from_utf8(bytes[2].clone()).unwrap(), sam);

        // Test getIter with manual conversion
        let mut iter_vals = Vec::new();
        for val_result in iosuber.get_iter::<_, Vec<u8>>(keys1)? {
            iter_vals.push(String::from_utf8(val_result?).unwrap());
        }
        assert_eq!(iter_vals.len(), 3);
        assert_eq!(iter_vals[0], sal);
        assert_eq!(iter_vals[1], sue);
        assert_eq!(iter_vals[2], sam);

        // Test getItemIter (for all items)
        let items: Vec<(Vec<Vec<u8>>, Vec<u8>)> = iosuber.get_item_iter(&[] as &[&str], false)?;
        assert_eq!(items.len(), 5);

        // Test values exist in expected orders
        let mut found_zoe = false;
        let mut found_zia = false;
        let mut found_sal_at_keys1 = false;
        let mut found_sue_at_keys1 = false;
        let mut found_sam_at_keys1 = false;

        for (keys, val) in &items {
            let key1 = String::from_utf8(keys[0].clone()).unwrap();
            let key2 = String::from_utf8(keys[1].clone()).unwrap();
            let val_str = String::from_utf8(val.clone()).unwrap();

            if key1 == "test_key" && key2 == "0001" && val_str == zoe {
                found_zoe = true;
            } else if key1 == "test_key" && key2 == "0001" && val_str == zia {
                found_zia = true;
            } else if key1 == "test_key" && key2 == "0002" && val_str == sal {
                found_sal_at_keys1 = true;
            } else if key1 == "test_key" && key2 == "0002" && val_str == sue {
                found_sue_at_keys1 = true;
            } else if key1 == "test_key" && key2 == "0002" && val_str == sam {
                found_sam_at_keys1 = true;
            }
        }

        assert!(found_zoe);
        assert!(found_zia);
        assert!(found_sal_at_keys1);
        assert!(found_sue_at_keys1);
        assert!(found_sam_at_keys1);

        // Test getFullItemIter
        let full_items = iosuber.get_full_item_iter(&[] as &[&str], false)?;
        assert_eq!(full_items.len(), 5);

        // Verify structure of first item
        let key1 = String::from_utf8(full_items[0].0[0].clone()).unwrap();
        let key2 = String::from_utf8(full_items[0].0[1].clone()).unwrap();
        let key3 = String::from_utf8(full_items[0].0[2].clone()).unwrap();

        assert_eq!(key1, "test_key");
        assert!(key2 == "0001" || key2 == "0002");
        assert!(key3.starts_with("0000000000000000"));

        // Test getItemIter with specific keys
        let items: Vec<(Vec<Vec<u8>>, Vec<u8>)> = iosuber.get_item_iter(keys0, false)?;
        assert_eq!(items.len(), 2);

        // Check that both keys0 items are returned with correct values
        let mut has_zoe = false;
        let mut has_zia = false;

        for (keys, val) in &items {
            let key1 = String::from_utf8(keys[0].clone()).unwrap();
            let key2 = String::from_utf8(keys[1].clone()).unwrap();
            let val_str = String::from_utf8(val.clone()).unwrap();

            assert_eq!(key1, "test_key");
            assert_eq!(key2, "0001");

            if val_str == zoe {
                has_zoe = true;
            } else if val_str == zia {
                has_zia = true;
            }
        }

        assert!(has_zoe);
        assert!(has_zia);

        // Test with keys1
        let items: Vec<(Vec<Vec<u8>>, Vec<u8>)> = iosuber.get_item_iter(keys1, false)?;
        assert_eq!(items.len(), 3);

        let mut has_sal = false;
        let mut has_sue = false;
        let mut has_sam = false;

        for (keys, val) in &items {
            let key1 = String::from_utf8(keys[0].clone()).unwrap();
            let key2 = String::from_utf8(keys[1].clone()).unwrap();
            let val_str = String::from_utf8(val.clone()).unwrap();

            assert_eq!(key1, "test_key");
            assert_eq!(key2, "0002");

            if val_str == sal {
                has_sal = true;
            } else if val_str == sue {
                has_sue = true;
            } else if val_str == sam {
                has_sam = true;
            }
        }

        assert!(has_sal);
        assert!(has_sue);
        assert!(has_sam);

        // Test with top keys
        assert!(iosuber.put(&["test", "pop"], &[&sal, &sue, &sam])?);
        let topkeys = &["test", ""];

        let items: Vec<(Vec<Vec<u8>>, Vec<u8>)> = iosuber.get_item_iter(topkeys, false)?;
        assert_eq!(items.len(), 3);

        // Verify test/pop entries
        let mut count = 0;
        for (keys, val) in &items {
            let key1 = String::from_utf8(keys[0].clone()).unwrap();
            let key2 = String::from_utf8(keys[1].clone()).unwrap();
            let val_str = String::from_utf8(val.clone()).unwrap();

            assert_eq!(key1, "test");
            assert_eq!(key2, "pop");
            assert!(val_str == sal || val_str == sue || val_str == sam);
            count += 1;
        }
        assert_eq!(count, 3);

        // Test with top parameter
        let keys = &["test"];

        let items: Vec<(Vec<Vec<u8>>, Vec<u8>)> = iosuber.get_item_iter(keys, true)?;
        assert_eq!(items.len(), 3);

        // Verify with top parameter
        for (keys, val) in &items {
            let key1 = String::from_utf8(keys[0].clone()).unwrap();
            let key2 = String::from_utf8(keys[1].clone()).unwrap();

            assert_eq!(key1, "test");
            assert_eq!(key2, "pop");
        }

        // Test remove with a specific val
        assert!(iosuber.rem(keys1, Some(&sue))?);

        let bytes: Vec<Vec<u8>> = iosuber.get(keys1)?;
        assert_eq!(bytes.len(), 2); // sue was removed
        assert_eq!(String::from_utf8(bytes[0].clone()).unwrap(), sal);
        assert_eq!(String::from_utf8(bytes[1].clone()).unwrap(), sam);

        // Test trim
        assert!(iosuber.trim(&["test", ""], true)?);

        // Verify test entries are gone
        let items: Vec<(Vec<Vec<u8>>, Vec<u8>)> = iosuber.get_item_iter(&["test"], true)?;
        assert_eq!(items.len(), 0);

        // Verify remaining entries
        let items: Vec<(Vec<Vec<u8>>, Vec<u8>)> = iosuber.get_item_iter(&[] as &[&str], true)?;
        assert_eq!(items.len(), 4); // keys0 (2) + keys1 (2)

        // Test with keys as string not tuple
        assert!(iosuber.put(keys2, &[&bob])?);
        let bytes: Vec<Vec<u8>> = iosuber.get(keys2)?;
        assert_eq!(bytes.len(), 1);
        assert_eq!(String::from_utf8(bytes[0].clone()).unwrap(), bob);
        assert_eq!(iosuber.cnt(keys2)?, 1);

        assert!(iosuber.rem(keys2, None::<&String>)?);
        let bytes: Vec<Vec<u8>> = iosuber.get(keys2)?;
        assert!(bytes.is_empty());
        assert_eq!(iosuber.cnt(keys2)?, 0);

        assert!(iosuber.put(keys2, &[&bob])?);
        let bytes: Vec<Vec<u8>> = iosuber.get(keys2)?;
        assert_eq!(String::from_utf8(bytes[0].clone()).unwrap(), bob);

        assert!(iosuber.pin(keys2, &[&bil])?);
        let bytes: Vec<Vec<u8>> = iosuber.get(keys2)?;
        assert_eq!(bytes.len(), 1);
        assert_eq!(String::from_utf8(bytes[0].clone()).unwrap(), bil);

        assert!(iosuber.add(keys2, &bob)?);
        let bytes: Vec<Vec<u8>> = iosuber.get(keys2)?;
        assert_eq!(bytes.len(), 2);
        assert_eq!(String::from_utf8(bytes[0].clone()).unwrap(), bil);
        assert_eq!(String::from_utf8(bytes[1].clone()).unwrap(), bob);

        // Test trim and append
        assert!(iosuber.trim(&[] as &[&str], false)?);
        assert!(iosuber.put(keys1, &[&bob, &bil])?);
        let bytes: Vec<Vec<u8>> = iosuber.get(keys1)?;
        assert_eq!(bytes.len(), 2);
        assert_eq!(String::from_utf8(bytes[0].clone()).unwrap(), bob);
        assert_eq!(String::from_utf8(bytes[1].clone()).unwrap(), bil);

        // The database should be closed and removed when db goes out of scope
        drop(db);

        Ok(())
    }
}
