pub mod cesr;
pub mod ioset;
pub mod serder;
pub mod signer;

use crate::errors::MatterError;
use crate::keri::db::dbing::BytesDatabase;
use crate::keri::db::dbing::LMDBer;
use crate::keri::db::errors::DBError;
use std::fmt::Debug;
use std::marker::PhantomData;
use std::sync::Arc;

// Error type for database operations
#[derive(Debug, thiserror::Error)]
pub enum SuberError {
    #[error("Database error: {0}")]
    DBError(#[from] DBError),

    #[error("Key conversion error: {0}")]
    KeyConversionError(String),

    #[error("Value conversion error: {0}")]
    ValueConversionError(String),

    #[error("Deserialization error: {0}")]
    DeserializationError(String),

    #[error("Encryption error: {0}")]
    EncryptionError(String),

    #[error("Encryption error: {0}")]
    DecryptionError(String),

    #[error("Verfer error: {0}")]
    VerferError(String),

    #[error("Matter error: {0}")]
    MatterError(#[from] MatterError),

    #[error("Empty Keys")]
    EmptyKeys,
}

// A trait for serialization/deserialization behavior
pub trait ValueCodec {
    // The error type used for serialization/deserialization errors
    type Error: std::error::Error + 'static;

    // Serialize a value to bytes
    fn serialize<T: ?Sized + Clone + Into<Vec<u8>>>(val: &T) -> Result<Vec<u8>, SuberError>;

    // Deserialize bytes to a value
    fn deserialize<T: TryFrom<Vec<u8>>>(bytes: &[u8]) -> Result<T, SuberError>;
}

// Default implementation for UTF-8 string serialization/deserialization
pub struct Utf8Codec;

impl From<std::convert::Infallible> for SuberError {
    fn from(_: std::convert::Infallible) -> Self {
        // This code will never run because Infallible can't be created
        unreachable!("This should never happen as Infallible cannot be instantiated")
    }
}

impl ValueCodec for Utf8Codec {
    type Error = SuberError;

    fn serialize<T: ?Sized + Clone + Into<Vec<u8>>>(val: &T) -> Result<Vec<u8>, SuberError> {
        // Implementation depends on T
        Ok(val.clone().into())
    }

    fn deserialize<T: TryFrom<Vec<u8>>>(bytes: &[u8]) -> Result<T, SuberError> {
        // Convert &[u8] to Vec<u8> first, then use try_from
        match T::try_from(bytes.to_vec()) {
            Ok(value) => Ok(value),
            Err(_) => Err(SuberError::DeserializationError(
                "Failed to convert bytes to the desired type".to_string(),
            )),
        }
    }
}

// The base struct for sub-database functionality
pub struct SuberBase<'db, C: ValueCodec = Utf8Codec> {
    db: Arc<&'db LMDBer>,   // The base LMDB database
    sdb: BytesDatabase,     // The sub-database
    sep: u8,                // Separator for combining keys
    verify: bool,           // Whether to verify data when deserializing
    _codec: PhantomData<C>, // Phantom data to track the codec type
}

impl<'db, C: ValueCodec> SuberBase<'db, C> {
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
            _codec: PhantomData,
        })
    }

    // Convert various key forms to bytes
    pub fn to_key<K: AsRef<[u8]>>(&self, keys: &[K], topive: bool) -> Vec<u8> {
        // Logic to convert keys to a single byte vector with separators
        // Similar to Python's _tokey method
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

    // Convert a key to a vector of key parts
    pub fn to_keys(&self, key: &[u8]) -> Vec<Vec<u8>> {
        // Logic to split key at separators
        // Similar to Python's _tokeys method
        key.split(|&b| b == self.sep)
            .map(|part| part.to_vec())
            .collect()
    }

    // Serialize a value to bytes
    pub fn ser<T: ?Sized + Clone + Into<Vec<u8>>>(&self, val: &T) -> Result<Vec<u8>, SuberError> {
        C::serialize(val)
    }

    // Deserialize bytes to a value
    pub fn des<T: TryFrom<Vec<u8>>>(&self, val: &[u8]) -> Result<T, SuberError> {
        C::deserialize(val)
    }

    // Common database operations

    // Remove entries with keys starting with a prefix
    pub fn trim<K: AsRef<[u8]>>(&self, keys: &[K], topive: bool) -> Result<bool, SuberError> {
        let key = self.to_key(keys, topive);
        Ok(self.db.del_top_val(&self.sdb, &key)?)
    }

    // Iterator for full items (with all parts visible)
    pub fn get_full_item_iter<K: AsRef<[u8]>>(
        &self,
        keys: &[K],
        topive: bool,
    ) -> Result<Vec<(Vec<Vec<u8>>, Vec<u8>)>, SuberError> {
        let key = self.to_key(keys, topive);

        let mut result = Vec::new();
        self.db.get_top_items_iter(&self.sdb, &key, |k, v| {
            result.push((self.to_keys(k), v.to_vec()));
            Ok(true) // Continue iteration for all items
        })?;

        Ok(result)
    }

    // Iterator for normal items (hiding implementation details)
    pub fn get_item_iter<K: AsRef<[u8]>>(
        &self,
        keys: &[K],
        topive: bool,
    ) -> Result<Vec<(Vec<Vec<u8>>, Vec<u8>)>, SuberError> {
        // By default, this is the same as get_full_item_iter
        // Subclasses would override this to hide implementation details
        self.get_full_item_iter(keys, topive)
    }

    // Count all items in the database
    pub fn cnt_all(&self) -> Result<usize, SuberError> {
        Ok(self.db.cnt(&self.sdb)?)
    }
}

// Suber - a subclass of SuberBase that doesn't allow duplicates
pub struct Suber<'a, C: ValueCodec = Utf8Codec> {
    base: SuberBase<'a, C>,
}

impl<'db, C: ValueCodec> Suber<'db, C> {
    pub fn new(
        db: Arc<&'db LMDBer>,
        subkey: &str,
        sep: Option<u8>,
        verify: bool,
    ) -> Result<Self, SuberError> {
        Ok(Self {
            base: SuberBase::new(db, subkey, sep, verify)?,
        })
    }

    // Put a value at keys (doesn't overwrite)
    pub fn put<K: AsRef<[u8]>, V: ?Sized + Clone + Into<Vec<u8>>>(
        &self,
        keys: &[K],
        val: &V,
    ) -> Result<bool, SuberError> {
        let key = self.base.to_key(keys, false);
        let val_bytes = self.base.ser(val)?;
        Ok(self.base.db.put_val(&self.base.sdb, &key, &val_bytes)?)
    }

    // Pin (set) a value at keys (overwrites)
    pub fn pin<K: AsRef<[u8]>, V: ?Sized + Clone + Into<Vec<u8>>>(
        &self,
        keys: &[K],
        val: &V,
    ) -> Result<bool, SuberError> {
        let key = self.base.to_key(keys, false);
        let val_bytes = self.base.ser(val)?;
        Ok(self.base.db.set_val(&self.base.sdb, &key, &val_bytes)?)
    }

    // Get a value at keys
    pub fn get<K: AsRef<[u8]>, V: TryFrom<Vec<u8>>>(
        &self,
        keys: &[K],
    ) -> Result<Option<V>, SuberError> {
        let key = self.base.to_key(keys, false);
        if let Some(val) = self.base.db.get_val(&self.base.sdb, &key)? {
            Ok(Some(self.base.des(&val)?))
        } else {
            Ok(None)
        }
    }

    // Remove an entry at keys
    pub fn rem<K: AsRef<[u8]>>(&self, keys: &[K]) -> Result<bool, SuberError> {
        let key = self.base.to_key(keys, false);
        Ok(self.base.db.del_val(&self.base.sdb, &key)?)
    }

    // Delegate methods to the base implementation
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keri::db::dbing::LMDBer;
    use crate::keri::db::subing::{Suber, SuberError};
    use std::sync::Arc;

    #[test]
    fn test_suber() -> Result<(), SuberError> {
        // Create a temporary directory for the test
        let lmdber = LMDBer::builder().name("test_db").temp(true).build()?;

        // Create "seen." database
        assert_eq!(lmdber.name(), "test_db");
        assert!(lmdber.opened());

        // Create Suber
        let suber: Suber<Utf8Codec> = Suber::new(Arc::new(&lmdber), "bags.", None, false)?;

        let sue = "Hello sailer!";

        // Test with tuple keys
        let keys: &[&[u8]] = &["test_key".as_bytes(), "0001".as_bytes()];
        suber.put(keys, &sue.as_bytes().to_vec())?;
        let actual = suber.get(keys).expect("Should return a string");
        assert_eq!(actual, Some(sue.as_bytes().to_vec()));

        suber.rem(keys)?;
        let actual: Option<Vec<u8>> = suber.get(keys).expect("Should return a string");
        assert_eq!(actual, None);

        suber.put(keys, &sue.as_bytes().to_vec())?;
        let actual = suber.get(keys).expect("Should return a string");
        assert_eq!(actual, Some(sue.as_bytes().to_vec()));

        let kip = "Hey gorgeous!";
        let result = suber.put(keys, &kip)?;
        assert!(!result);
        let actual = suber.get(keys).expect("Should return a string");
        assert_eq!(actual, Some(sue.as_bytes().to_vec()));

        let result = suber.pin(keys, &kip)?;
        assert!(result);
        let actual = suber.get(keys)?;
        assert_eq!(actual, Some(kip.as_bytes().to_vec()));

        suber.rem(keys)?;
        let actual: Option<Vec<u8>> = suber.get(keys)?;
        assert_eq!(actual, None);

        suber.put(keys, &sue)?;
        let actual = suber.get(keys)?;
        assert_eq!(actual, Some(sue.as_bytes().to_vec()));

        // Test with keys as tuple of bytes
        let byte_keys = &[b"test_key".to_vec(), b"0001".to_vec()];
        suber.rem(byte_keys)?;
        let actual: Option<Vec<u8>> = suber.get(byte_keys)?;
        assert_eq!(actual, None);

        suber.put(byte_keys, &sue)?;
        let actual: Option<Vec<u8>> = suber.get(byte_keys)?;
        assert_eq!(actual, Some(sue.as_bytes().to_vec()));

        // Test with keys as mixed tuple of bytes and strings
        let mixed_keys = &[b"test_key".to_vec(), b"0001".to_vec()];
        suber.rem(mixed_keys)?;
        let actual: Option<Vec<u8>> = suber.get(mixed_keys)?;
        assert_eq!(actual, None);

        suber.put(mixed_keys, &sue)?;
        let actual: Option<Vec<u8>> = suber.get(mixed_keys)?;
        assert_eq!(actual, Some(sue.as_bytes().to_vec()));

        // Test with keys as string not tuple
        let key_str = &["keystr"];
        let bob = "Shove off!";

        suber.put(key_str, &bob)?;
        let actual: Option<Vec<u8>> = suber.get(key_str)?;
        assert_eq!(actual, Some(bob.as_bytes().to_vec()));

        suber.rem(key_str)?;
        let actual: Option<Vec<u8>> = suber.get(key_str)?;
        assert_eq!(actual, None);

        let liz = "May life is insane.";
        let liz_keys = &["test_key", "0002"];

        suber.put(liz_keys, &liz)?;
        let not_found_keys = &["not_found", "0002"];
        let actual: Option<Vec<u8>> = suber.get(not_found_keys)?;
        assert_eq!(actual, None);

        let w = "Blue dog";
        let x = "Green tree";
        let y = "Red apple";
        let z = "White snow";

        // // Create a new Suber instance with different subkey
        let suber: Suber<'_, Utf8Codec> = Suber::new(Arc::new(&lmdber), "pugs.", None, false)?;

        suber.put(&["a", "1"], &w)?;
        suber.put(&["a", "2"], &x)?;
        suber.put(&["a", "3"], &y)?;
        suber.put(&["a", "4"], &z)?;

        // Get all items
        let ekey: &[u8] = &[];
        let items = suber.get_item_iter(&[ekey], false)?;
        let items_vec: Vec<(Vec<Vec<u8>>, String)> = items
            .into_iter()
            .map(|(keys, val)| {
                let string_val = String::from_utf8(val).unwrap();
                (keys, string_val)
            })
            .collect();

        // Convert to a format we can compare with assert_eq
        let expected = vec![
            (vec![b"a".to_vec(), b"1".to_vec()], w.to_string()),
            (vec![b"a".to_vec(), b"2".to_vec()], x.to_string()),
            (vec![b"a".to_vec(), b"3".to_vec()], y.to_string()),
            (vec![b"a".to_vec(), b"4".to_vec()], z.to_string()),
        ];

        assert_eq!(items_vec, expected);

        // suber.put(&["b", "1"], &w)?;
        // suber.put(&["b", "2"], &x)?;
        // suber.put(&["bc", "3"], &y)?;
        // suber.put(&["ac", "4"], &z)?;
        //
        // let items = suber.get_item_iter(&[], false)?;
        // let items_vec: Vec<(Vec<String>, String)> = items
        //     .into_iter()
        //     .map(|(keys, val)| {
        //         let string_keys = keys
        //             .into_iter()
        //             .map(|k| String::from_utf8(k).unwrap())
        //             .collect();
        //         let string_val = String::from_utf8(val).unwrap();
        //         (string_keys, string_val)
        //     })
        //     .collect();
        //
        // let expected = vec![
        //     (vec!["a".to_string(), "1".to_string()], "Blue dog".to_string()),
        //     (vec!["a".to_string(), "2".to_string()], "Green tree".to_string()),
        //     (vec!["a".to_string(), "3".to_string()], "Red apple".to_string()),
        //     (vec!["a".to_string(), "4".to_string()], "White snow".to_string()),
        //     (vec!["ac".to_string(), "4".to_string()], "White snow".to_string()),
        //     (vec!["b".to_string(), "1".to_string()], "Blue dog".to_string()),
        //     (vec!["b".to_string(), "2".to_string()], "Green tree".to_string()),
        //     (vec!["bc".to_string(), "3".to_string()], "Red apple".to_string()),
        // ];
        //
        // assert_eq!(items_vec, expected);
        //
        // // Test with top keys for partial tree
        // let topkeys = &["b", ""];
        // let items = suber.get_item_iter(topkeys, false)?;
        // let items_vec: Vec<(Vec<String>, String)> = items
        //     .into_iter()
        //     .map(|(keys, val)| {
        //         let string_keys = keys
        //             .into_iter()
        //             .map(|k| String::from_utf8(k).unwrap())
        //             .collect();
        //         let string_val = String::from_utf8(val).unwrap();
        //         (string_keys, string_val)
        //     })
        //     .collect();
        //
        // let expected = vec![
        //     (vec!["b".to_string(), "1".to_string()], w.to_string()),
        //     (vec!["b".to_string(), "2".to_string()], x.to_string()),
        // ];
        //
        // assert_eq!(items_vec, expected);
        //
        // let topkeys = &["a", ""];
        // let items = suber.get_item_iter(topkeys, false)?;
        // let items_vec: Vec<(Vec<String>, String)> = items
        //     .into_iter()
        //     .map(|(keys, val)| {
        //         let string_keys = keys
        //             .into_iter()
        //             .map(|k| String::from_utf8(k).unwrap())
        //             .collect();
        //         let string_val = String::from_utf8(val).unwrap();
        //         (string_keys, string_val)
        //     })
        //     .collect();
        //
        // let expected = vec![
        //     (vec!["a".to_string(), "1".to_string()], w.to_string()),
        //     (vec!["a".to_string(), "2".to_string()], x.to_string()),
        //     (vec!["a".to_string(), "3".to_string()], y.to_string()),
        //     (vec!["a".to_string(), "4".to_string()], z.to_string()),
        // ];
        //
        // assert_eq!(items_vec, expected);
        //
        // // Test with topive parameter
        // let keys = &["b"];
        // let items = suber.get_item_iter(keys, true)?;
        // let items_vec: Vec<(Vec<String>, String)> = items
        //     .into_iter()
        //     .map(|(keys, val)| {
        //         let string_keys = keys
        //             .into_iter()
        //             .map(|k| String::from_utf8(k).unwrap())
        //             .collect();
        //         let string_val = String::from_utf8(val).unwrap();
        //         (string_keys, string_val)
        //     })
        //     .collect();
        //
        // let expected = vec![
        //     (vec!["b".to_string(), "1".to_string()], w.to_string()),
        //     (vec!["b".to_string(), "2".to_string()], x.to_string()),
        // ];
        //
        // assert_eq!(items_vec, expected);
        //
        // let keys = &["a"];
        // let items = suber.get_item_iter(keys, true)?;
        // let items_vec: Vec<(Vec<String>, String)> = items
        //     .into_iter()
        //     .map(|(keys, val)| {
        //         let string_keys = keys
        //             .into_iter()
        //             .map(|k| String::from_utf8(k).unwrap())
        //             .collect();
        //         let string_val = String::from_utf8(val).unwrap();
        //         (string_keys, string_val)
        //     })
        //     .collect();
        //
        // let expected = vec![
        //     (vec!["a".to_string(), "1".to_string()], w.to_string()),
        //     (vec!["a".to_string(), "2".to_string()], x.to_string()),
        //     (vec!["a".to_string(), "3".to_string()], y.to_string()),
        //     (vec!["a".to_string(), "4".to_string()], z.to_string()),
        // ];
        //
        // assert_eq!(items_vec, expected);
        //
        // // Test trim
        // assert!(suber.trim(&["b", ""], false)?);
        // let items = suber.get_item_iter(&[], false)?;
        // let items_vec: Vec<(Vec<String>, String)> = items
        //     .into_iter()
        //     .map(|(keys, val)| {
        //         let string_keys = keys
        //             .into_iter()
        //             .map(|k| String::from_utf8(k).unwrap())
        //             .collect();
        //         let string_val = String::from_utf8(val).unwrap();
        //         (string_keys, string_val)
        //     })
        //     .collect();
        //
        // let expected = vec![
        //     (vec!["a".to_string(), "1".to_string()], "Blue dog".to_string()),
        //     (vec!["a".to_string(), "2".to_string()], "Green tree".to_string()),
        //     (vec!["a".to_string(), "3".to_string()], "Red apple".to_string()),
        //     (vec!["a".to_string(), "4".to_string()], "White snow".to_string()),
        //     (vec!["ac".to_string(), "4".to_string()], "White snow".to_string()),
        //     (vec!["bc".to_string(), "3".to_string()], "Red apple".to_string()),
        // ];
        //
        // assert_eq!(items_vec, expected);
        //
        // assert!(suber.trim(&["a", ""], false)?);
        // let items = suber.get_item_iter(&[], false)?;
        // let items_vec: Vec<(Vec<String>, String)> = items
        //     .into_iter()
        //     .map(|(keys, val)| {
        //         let string_keys = keys
        //             .into_iter()
        //             .map(|k| String::from_utf8(k).unwrap())
        //             .collect();
        //         let string_val = String::from_utf8(val).unwrap();
        //         (string_keys, string_val)
        //     })
        //     .collect();
        //
        // let expected = vec![
        //     (vec!["ac".to_string(), "4".to_string()], "White snow".to_string()),
        //     (vec!["bc".to_string(), "3".to_string()], "Red apple".to_string()),
        // ];
        //
        // assert_eq!(items_vec, expected);
        //
        // // Test trim with top parameters
        // suber.put(&["a", "1"], &w)?;
        // suber.put(&["a", "2"], &x)?;
        // suber.put(&["a", "3"], &y)?;
        // suber.put(&["a", "4"], &z)?;
        // suber.put(&["b", "1"], &w)?;
        // suber.put(&["b", "2"], &x)?;
        //
        // assert!(suber.trim(&["b"], true)?);
        // let items = suber.get_item_iter(&[], false)?;
        // let items_vec: Vec<(Vec<String>, String)> = items
        //     .into_iter()
        //     .map(|(keys, val)| {
        //         let string_keys = keys
        //             .into_iter()
        //             .map(|k| String::from_utf8(k).unwrap())
        //             .collect();
        //         let string_val = String::from_utf8(val).unwrap();
        //         (string_keys, string_val)
        //     })
        //     .collect();
        //
        // let expected = vec![
        //     (vec!["a".to_string(), "1".to_string()], "Blue dog".to_string()),
        //     (vec!["a".to_string(), "2".to_string()], "Green tree".to_string()),
        //     (vec!["a".to_string(), "3".to_string()], "Red apple".to_string()),
        //     (vec!["a".to_string(), "4".to_string()], "White snow".to_string()),
        //     (vec!["ac".to_string(), "4".to_string()], "White snow".to_string()),
        //     (vec!["bc".to_string(), "3".to_string()], "Red apple".to_string()),
        // ];
        //
        // assert_eq!(items_vec, expected);
        //
        // assert!(suber.trim(&["a"], true)?);
        // let items = suber.get_item_iter(&[], false)?;
        // let items_vec: Vec<(Vec<String>, String)> = items
        //     .into_iter()
        //     .map(|(keys, val)| {
        //         let string_keys = keys
        //             .into_iter()
        //             .map(|k| String::from_utf8(k).unwrap())
        //             .collect();
        //         let string_val = String::from_utf8(val).unwrap();
        //         (string_keys, string_val)
        //     })
        //     .collect();
        //
        // let expected = vec![
        //     (vec!["ac".to_string(), "4".to_string()], "White snow".to_string()),
        //     (vec!["bc".to_string(), "3".to_string()], "Red apple".to_string()),
        // ];
        //
        // assert_eq!(items_vec, expected);
        //
        // assert!(suber.trim(&[], false)?);
        // let items = suber.get_item_iter(&[], false)?;
        // let items_vec: Vec<(Vec<String>, String)> = items
        //     .into_iter()
        //     .map(|(keys, val)| {
        //         let string_keys = keys
        //             .into_iter()
        //             .map(|k| String::from_utf8(k).unwrap())
        //             .collect();
        //         let string_val = String::from_utf8(val).unwrap();
        //         (string_keys, string_val)
        //     })
        //     .collect();
        //
        // assert_eq!(items_vec, vec![]);
        //
        // assert!(!suber.trim(&[], false)?);
        //
        // // Close database
        // drop(lmdber);
        //
        Ok(())
    }
}
