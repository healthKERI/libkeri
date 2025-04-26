use crate::keri::db::dbing::LMDBer;
use crate::keri::db::subing::{SuberBase, SuberError, Utf8Codec, ValueCodec};
use std::sync::Arc;

/// Represents a Duplicate Suber, allowing multiple values (duplicates) at each key.
///
/// Do not use if serialized value is greater than 511 bytes.
/// This is a limitation of dupsort==True sub dbs in LMDB.
pub struct DupSuber<'db, C: ValueCodec = Utf8Codec> {
    base: SuberBase<'db, C>,
}

impl<'db, C: ValueCodec> DupSuber<'db, C> {
    /// Creates a new `DupSuber`.
    pub fn new(
        db: Arc<&'db LMDBer>,
        subkey: &str,
        sep: Option<u8>,
        verify: bool,
    ) -> Result<Self, SuberError> {
        // Always use dupsort=True for DupSuber
        let base = SuberBase::new(db, subkey, sep, verify, Some(true))?;

        Ok(Self { base })
    }

    pub fn is_dupsort(&self) -> bool {
        self.base.is_dupsort()
    }

    /// Puts all vals at key made from keys. Does not overwrite. Adds to existing
    /// dup values at key if any. Duplicate means another entry at the same key
    /// but the entry is still a unique value. Duplicates are inserted in
    /// lexicographic order not insertion order. LMDB does not insert a duplicate
    /// unless it is a unique value for that key.
    pub fn put<K: AsRef<[u8]>, V: ?Sized + Clone + Into<Vec<u8>>>(
        &self,
        keys: &[K],
        vals: &[&V],
    ) -> Result<bool, SuberError> {
        let key = self.base.to_key(keys, false);

        // Serialize all values
        let serialized_vals: Vec<Vec<u8>> = vals
            .iter()
            .map(|v| self.base.ser(*v))
            .collect::<Result<Vec<Vec<u8>>, _>>()?;

        // Create Vec<&[u8]> by borrowing from serialized_vals
        let val_slices: Vec<&[u8]> = serialized_vals.iter().map(|v| v.as_slice()).collect();

        // Use the put_vals method for dup databases
        self.base
            .db
            .put_vals(&self.base.sdb, &key, &val_slices)
            .map_err(SuberError::DBError)
    }

    /// Add val to vals at key made from keys. Does not overwrite. Adds to existing
    /// dup values at key if any. Duplicate means another entry at the same key
    /// but the entry is still a unique value. Duplicates are inserted in
    /// lexicographic order not insertion order. LMDB does not insert a duplicate
    /// unless it is a unique value for that key.
    pub fn add<K: AsRef<[u8]>, V: ?Sized + Clone + Into<Vec<u8>>>(
        &self,
        keys: &[K],
        val: &V,
    ) -> Result<bool, SuberError> {
        let key = self.base.to_key(keys, false);
        let sval = self.base.ser(val)?;

        self.base
            .db
            .add_val(&self.base.sdb, &key, &sval)
            .map_err(SuberError::DBError)
    }

    /// Pins (sets) vals at key made from keys. Overwrites. Removes all
    /// pre-existing dup vals and replaces them with vals.
    pub fn pin<K: AsRef<[u8]>, V: ?Sized + Clone + Into<Vec<u8>>>(
        &self,
        keys: &[K],
        vals: &[&V],
    ) -> Result<bool, SuberError> {
        let key = self.base.to_key(keys, false);

        // First delete all values at the key
        self.base
            .db
            .del_vals(&self.base.sdb, &key, None)
            .map_err(SuberError::DBError)?;

        // If we have no values to add, just return true (successful deletion)
        if vals.is_empty() {
            return Ok(true);
        }

        // Serialize all values
        let serialized_vals: Vec<Vec<u8>> = vals
            .iter()
            .map(|v| self.base.ser(*v))
            .collect::<Result<Vec<Vec<u8>>, _>>()?;

        // Create Vec<&[u8]> by borrowing from serialized_vals
        let val_slices: Vec<&[u8]> = serialized_vals.iter().map(|v| v.as_slice()).collect();

        // Add the new values
        self.base
            .db
            .put_vals(&self.base.sdb, &key, &val_slices)
            .map_err(SuberError::DBError)
    }

    /// Gets dup vals list at key made from keys.
    pub fn get<K: AsRef<[u8]>, R: TryFrom<Vec<u8>>>(&self, keys: &[K]) -> Result<Vec<R>, SuberError>
    where
        <R as TryFrom<Vec<u8>>>::Error: std::fmt::Debug,
    {
        let key = self.base.to_key(keys, false);
        let mut raw_vals: Vec<Vec<u8>> = Vec::new();

        self.base
            .db
            .get_vals_iter(&self.base.sdb, &key, |val| {
                raw_vals.push(val.to_vec());
                Ok(true)
            })
            .map_err(SuberError::DBError)?;

        raw_vals
            .iter()
            .map(|raw_val| self.base.des(raw_val))
            .collect() // Collects into Result<Vec<R>, SuberError>
    }

    /// Gets the last duplicate value at key made from keys
    ///
    /// # Arguments
    ///
    /// * `keys`: An array slice of key parts to be combined to form key
    ///
    /// # Returns
    ///
    /// `Result<Option<R>, SuberError>` - Deserialized value if found, None if no value at key,
    /// or an error if deserialization fails
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
            .get_val_last(&self.base.sdb, &key)
            .map_err(SuberError::DBError)?;

        match raw_val_opt {
            Some(val) => self.base.des(&val).map(Some),
            None => Ok(None),
        }
    }

    /// Gets dup vals iterator at key made from keys.
    /// Duplicates are retrieved in lexicographic order not insertion order.
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

        self.base
            .db
            .get_vals_iter(&self.base.sdb, &key, |val| {
                let result = self.base.des(val);
                results.push(result);
                Ok(true)
            })
            .map_err(SuberError::DBError)?;

        Ok(results.into_iter())
    }

    pub fn get_item_iter<K: AsRef<[u8]>>(
        &self,
        keys: &[K],
        topive: bool,
    ) -> Result<Vec<(Vec<Vec<u8>>, Vec<u8>)>, SuberError> {
        Ok(self.base.get_item_iter(keys, topive)?)
    }

    /// Return count of dup values at key made from keys, zero otherwise
    pub fn cnt<K: AsRef<[u8]>>(&self, keys: &[K]) -> Result<usize, SuberError> {
        let key = self.base.to_key(keys, false);
        self.base
            .db
            .cnt_vals(&self.base.sdb, &key)
            .map_err(SuberError::DBError)
    }

    /// Removes entry or specific value at keys
    ///
    /// If val is provided, remove only that value at the key.
    /// If val is None, remove all values at the key.
    pub fn rem<K: AsRef<[u8]>, V: ?Sized + Clone + Into<Vec<u8>>>(
        &self,
        keys: &[K],
        val: Option<&V>,
    ) -> Result<bool, SuberError> {
        let key = self.base.to_key(keys, false);

        match val {
            Some(v) => {
                let sval = self.base.ser(v)?;
                self.base
                    .db
                    .del_vals(&self.base.sdb, &key, Some(&sval))
                    .map_err(SuberError::DBError)
            }
            None => self
                .base
                .db
                .del_vals(&self.base.sdb, &key, None)
                .map_err(SuberError::DBError),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keri::db::dbing::keys::on_key;

    #[test]
    fn test_dup_suber() -> Result<(), SuberError> {
        // Create a temporary database
        let db = LMDBer::builder()
            .temp(true)
            .name("test")
            .build()
            .map_err(SuberError::DBError)?;
        let db_ref = Arc::new(&db);

        // Create a DupSuber
        let dupber: DupSuber<Utf8Codec> = DupSuber::new(db_ref.clone(), "bags.", None, false)?;

        assert!(dupber.is_dupsort());

        // Define test values
        let sue = "Hello sailer!";
        let sal = "Not my type.";

        // Test keys
        let keys0 = ["test_key", "0001"];
        let keys1 = ["test_key", "0002"];

        // Test put and get
        dupber.put(&keys0, &[&sue, &sal])?;
        let bytes: Vec<Vec<u8>> = dupber.get(&keys0)?;
        assert_eq!(bytes.len(), 2);
        // Compare individual strings
        assert_eq!(String::from_utf8(bytes[0].clone()).unwrap(), sue);
        assert_eq!(String::from_utf8(bytes[1].clone()).unwrap(), sal);
        assert_eq!(dupber.cnt(&keys0)?, 2);

        // Test rem
        dupber.rem(&keys0, None::<&String>)?;
        let bytes: Vec<Vec<u8>> = dupber.get(&keys0)?;
        assert!(bytes.is_empty());
        assert_eq!(dupber.cnt(&keys0)?, 0);

        // Test put and get with different order - should still sort lexicographically
        dupber.put(&keys0, &[&sal, &sue])?;
        let bytes: Vec<Vec<u8>> = dupber.get(&keys0)?;
        assert_eq!(bytes.len(), 2);
        assert_eq!(String::from_utf8(bytes[0].clone()).unwrap(), sue);
        assert_eq!(String::from_utf8(bytes[1].clone()).unwrap(), sal);

        // Test getLast
        let last_bytes: Option<Vec<u8>> = dupber.get_last(&keys0)?;
        assert!(last_bytes.is_some());
        assert_eq!(String::from_utf8(last_bytes.unwrap()).unwrap(), sal);

        // Test add
        let sam = "A real charmer!";
        let result = dupber.add(&keys0, &sam)?;
        assert!(result);
        let bytes: Vec<Vec<u8>> = dupber.get(&keys0)?;
        assert_eq!(bytes.len(), 3);
        assert_eq!(String::from_utf8(bytes[0].clone()).unwrap(), sam);
        assert_eq!(String::from_utf8(bytes[1].clone()).unwrap(), sue);
        assert_eq!(String::from_utf8(bytes[2].clone()).unwrap(), sal);

        // Test pin (replaces existing values)
        let zoe = "See ya later.";
        let zia = "Hey gorgeous!";
        let result = dupber.pin(&keys0, &[&zoe, &zia])?;
        assert!(result);
        let bytes: Vec<Vec<u8>> = dupber.get(&keys0)?;
        assert_eq!(bytes.len(), 2);
        assert_eq!(String::from_utf8(bytes[0].clone()).unwrap(), zia);
        assert_eq!(String::from_utf8(bytes[1].clone()).unwrap(), zoe);

        // Test with more values
        dupber.put(&keys1, &[&sal, &sue, &sam])?;
        let bytes: Vec<Vec<u8>> = dupber.get(&keys1)?;
        assert_eq!(bytes.len(), 3);
        assert_eq!(String::from_utf8(bytes[0].clone()).unwrap(), sam);
        assert_eq!(String::from_utf8(bytes[1].clone()).unwrap(), sue);
        assert_eq!(String::from_utf8(bytes[2].clone()).unwrap(), sal);

        // Test iterator
        let iter = dupber.get_iter::<_, Vec<u8>>(&keys1)?;
        let iter_bytes: Vec<Vec<u8>> = iter.collect::<Result<Vec<_>, _>>()?;
        assert_eq!(iter_bytes.len(), 3);
        assert_eq!(String::from_utf8(iter_bytes[0].clone()).unwrap(), sam);
        assert_eq!(String::from_utf8(iter_bytes[1].clone()).unwrap(), sue);
        assert_eq!(String::from_utf8(iter_bytes[2].clone()).unwrap(), sal);

        // Test get_item_iter with correct parameters
        let items: Vec<(Vec<Vec<u8>>, Vec<u8>)> = dupber.get_item_iter::<&str>(&[], true)?;

        // Convert the bytes to strings for easier assertions
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

        // Assert that we have the expected items
        assert_eq!(items_as_strings.len(), 5);
        assert!(items_as_strings.contains(&(
            vec!["test_key".to_string(), "0001".to_string()],
            "Hey gorgeous!".to_string()
        )));
        assert!(items_as_strings.contains(&(
            vec!["test_key".to_string(), "0001".to_string()],
            "See ya later.".to_string()
        )));
        assert!(items_as_strings.contains(&(
            vec!["test_key".to_string(), "0002".to_string()],
            "A real charmer!".to_string()
        )));
        assert!(items_as_strings.contains(&(
            vec!["test_key".to_string(), "0002".to_string()],
            "Hello sailer!".to_string()
        )));
        assert!(items_as_strings.contains(&(
            vec!["test_key".to_string(), "0002".to_string()],
            "Not my type.".to_string()
        )));

        // Add test with ("test", "blue") keys as in the Python test
        assert!(dupber.put(&["test", "blue"], &[&sal, &sue, &sam])?);

        // Test getting items with a prefix - similar to the Python test's usage of topkeys
        let topkeys = ["test", ""];
        let prefix_items: Vec<(Vec<Vec<u8>>, Vec<u8>)> = dupber.get_item_iter(&topkeys, true)?;

        // Convert to strings for easier assertions
        let prefix_items_as_strings: Vec<(Vec<String>, String)> = prefix_items
            .into_iter()
            .map(|(keys_bytes, val_bytes)| {
                let parsed_keys = keys_bytes
                    .into_iter()
                    .map(|k| String::from_utf8(k).unwrap())
                    .collect();
                (parsed_keys, String::from_utf8(val_bytes).unwrap())
            })
            .collect();

        // Assert we have the correct items with the test prefix
        assert_eq!(prefix_items_as_strings.len(), 3);
        assert!(prefix_items_as_strings.contains(&(
            vec!["test".to_string(), "blue".to_string()],
            "A real charmer!".to_string()
        )));
        assert!(prefix_items_as_strings.contains(&(
            vec!["test".to_string(), "blue".to_string()],
            "Hello sailer!".to_string()
        )));
        assert!(prefix_items_as_strings.contains(&(
            vec!["test".to_string(), "blue".to_string()],
            "Not my type.".to_string()
        )));

        // Test with string key (not tuple)
        let keys2 = ["keystr"];
        let bob = "Shove off!";
        dupber.put(&keys2, &[&bob])?;
        let bytes: Vec<Vec<u8>> = dupber.get(&keys2)?;
        assert_eq!(bytes.len(), 1);
        assert_eq!(String::from_utf8(bytes[0].clone()).unwrap(), bob);
        assert_eq!(dupber.cnt(&keys2)?, 1);

        // Test removal of string key
        dupber.rem(&keys2, None::<&String>)?;
        let bytes: Vec<Vec<u8>> = dupber.get(&keys2)?;
        assert!(bytes.is_empty());
        assert_eq!(dupber.cnt(&keys2)?, 0);

        // Test put and pin with string key
        dupber.put(&keys2, &[&bob])?;
        let bytes: Vec<Vec<u8>> = dupber.get(&keys2)?;
        assert_eq!(bytes.len(), 1);
        assert_eq!(String::from_utf8(bytes[0].clone()).unwrap(), bob);

        let bil = "Go away.";
        dupber.pin(&keys2, &[&bil])?;
        let bytes: Vec<Vec<u8>> = dupber.get(&keys2)?;
        assert_eq!(bytes.len(), 1);
        assert_eq!(String::from_utf8(bytes[0].clone()).unwrap(), bil);

        // Test add with string key
        dupber.add(&keys2, &bob)?;
        let bytes: Vec<Vec<u8>> = dupber.get(&keys2)?;
        assert_eq!(bytes.len(), 2);
        assert_eq!(String::from_utf8(bytes[0].clone()).unwrap(), bil);
        assert_eq!(String::from_utf8(bytes[1].clone()).unwrap(), bob);

        // Test with multiple values per key using on_key
        let vals1 = ["hi", "me", "my"];
        for (i, val) in vals1.iter().enumerate() {
            let key = on_key("bob", i as u64, None);
            assert!(dupber.put(&[&key], &[val])?);
        }

        let vals2 = ["bye", "guy", "gal"];
        for (i, val) in vals2.iter().enumerate() {
            let key = on_key("bob", i as u64, None);
            assert!(dupber.put(&[&key], &[val])?);
        }

        // Test getting items with "bob" prefix
        let bob_items: Vec<(Vec<Vec<u8>>, Vec<u8>)> = dupber.get_item_iter(&["bob"], true)?;

        // Convert to strings for easier assertions
        let bob_items_as_strings: Vec<(Vec<String>, String)> = bob_items
            .into_iter()
            .map(|(keys_bytes, val_bytes)| {
                let parsed_keys = keys_bytes
                    .into_iter()
                    .map(|k| String::from_utf8(k).unwrap())
                    .collect();
                (parsed_keys, String::from_utf8(val_bytes).unwrap())
            })
            .collect();

        // Check all "bob" prefix items match expected
        assert_eq!(bob_items_as_strings.len(), 6);
        assert!(bob_items_as_strings.contains(&(
            vec![
                "bob".to_string(),
                "00000000000000000000000000000000".to_string()
            ],
            "bye".to_string()
        )));
        assert!(bob_items_as_strings.contains(&(
            vec![
                "bob".to_string(),
                "00000000000000000000000000000000".to_string()
            ],
            "hi".to_string()
        )));
        assert!(bob_items_as_strings.contains(&(
            vec![
                "bob".to_string(),
                "00000000000000000000000000000001".to_string()
            ],
            "guy".to_string()
        )));
        assert!(bob_items_as_strings.contains(&(
            vec![
                "bob".to_string(),
                "00000000000000000000000000000001".to_string()
            ],
            "me".to_string()
        )));
        assert!(bob_items_as_strings.contains(&(
            vec![
                "bob".to_string(),
                "00000000000000000000000000000002".to_string()
            ],
            "gal".to_string()
        )));
        assert!(bob_items_as_strings.contains(&(
            vec![
                "bob".to_string(),
                "00000000000000000000000000000002".to_string()
            ],
            "my".to_string()
        )));

        // Test count of values for a specific key
        let key1 = on_key("bob", 1, None);
        assert_eq!(dupber.cnt(&[&key1])?, 2);

        // Test get iterator for specific key
        let key2 = on_key("bob", 2, None);
        let iter = dupber.get_iter::<_, Vec<u8>>(&[&key2])?;
        let vals: Vec<Vec<u8>> = iter.collect::<Result<Vec<_>, _>>()?;
        // Then convert to strings if needed
        let vals_as_strings: Vec<String> = vals
            .into_iter()
            .map(|bytes| String::from_utf8(bytes).unwrap())
            .collect();

        assert_eq!(vals_as_strings.len(), 2);
        assert_eq!(vals_as_strings[0], "gal");
        assert_eq!(vals_as_strings[1], "my");

        // The database should be removed when db goes out of scope
        Ok(())
    }
}
