use crate::keri::db::dbing::LMDBer;
use crate::keri::db::errors::DBError;
use heed::types::*;
use heed::Database;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use std::marker::PhantomData;
use std::sync::Arc;
use thiserror::Error;

#[allow(dead_code)]
#[derive(Debug, Error)]
pub enum KomerError {
    #[error("Database error: {0}")]
    Database(#[from] heed::Error),

    #[error("LMDB error: {0}")]
    DBError(#[from] DBError),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Deserialization error: {0}")]
    Deserialization(String),

    #[error("Invalid schema: expected {expected} got {got}")]
    InvalidSchema { expected: String, got: String },

    #[error("Empty keys")]
    EmptyKeys,
}

/// Serialization types supported
#[allow(dead_code)]
#[derive(Debug, Clone, Copy)]
pub enum SerialKind {
    Json,
    MsgPack,
    Cbor,
}

/// KomerBase is a base struct for Komer (Keyspace Object Mapper) implementations
/// that each use a struct (with Serialize/Deserialize) as the object mapped via
/// serialization to an LMDB database.
pub struct KomerBase<'db, T>
where
    T: Serialize + for<'de> Deserialize<'de> + Debug,
{
    /// LMDB database environment
    db: Arc<&'db LMDBer>, // The base LMDB database

    /// LMDB database instance for this Komer
    pub sdb: Database<Bytes, Bytes>,

    /// Serialization format
    pub kind: SerialKind,

    /// Separator for combining keys
    pub sep: String,

    /// Phantom data for the schema type
    phantom: PhantomData<&'db T>,
}

impl<'db, T> KomerBase<'db, T>
where
    T: Serialize + for<'de> Deserialize<'de> + Debug,
{
    /// Create a new KomerBase instance
    pub fn new(
        db: Arc<&'db LMDBer>,
        subkey: &str,
        kind: SerialKind,
        dupsort: bool,
        sep: Option<&str>,
    ) -> Result<Self, KomerError> {
        let sdb = db.create_database(Some(subkey), Some(dupsort))?;

        Ok(Self {
            db,
            sdb,
            kind,
            sep: sep.unwrap_or(".").to_string(),
            phantom: PhantomData,
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
            result.push(self.sep.as_bytes()[0]);
            return result;
        }

        // Join multiple keys with separators
        for (i, key) in keys.iter().enumerate() {
            if i > 0 {
                result.push(self.sep.as_bytes()[0]);
            }
            result.extend_from_slice(key.as_ref());
        }

        // Add trailing separator for topive
        if topive && (!result.is_empty() && result[result.len() - 1] != self.sep.as_bytes()[0]) {
            result.push(self.sep.as_bytes()[0]);
        }

        result
    }

    /// Converts key bytes to keys tuple of strings
    pub fn to_keys(&self, key: &[u8]) -> Vec<String> {
        let key_str = String::from_utf8_lossy(key);
        key_str.split(&self.sep).map(String::from).collect()
    }

    /// Serialize a value using the configured serializer
    pub fn serialize(&self, val: &T) -> Result<Vec<u8>, KomerError> {
        match self.kind {
            SerialKind::Json => self.serialize_json(val),
            SerialKind::MsgPack => self.serialize_msgpack(val),
            SerialKind::Cbor => self.serialize_cbor(val),
        }
    }

    /// Deserialize a value using the configured deserializer
    pub fn deserialize(&self, val: &[u8]) -> Result<T, KomerError> {
        match self.kind {
            SerialKind::Json => self.deserialize_json(val),
            SerialKind::MsgPack => self.deserialize_msgpack(val),
            SerialKind::Cbor => self.deserialize_cbor(val),
        }
    }

    /// Serialize to JSON
    fn serialize_json(&self, val: &T) -> Result<Vec<u8>, KomerError> {
        serde_json::to_vec(val)
            .map_err(|e| KomerError::Serialization(format!("JSON serialization error: {}", e)))
    }

    /// Deserialize from JSON
    fn deserialize_json(&self, val: &[u8]) -> Result<T, KomerError> {
        serde_json::from_slice(val)
            .map_err(|e| KomerError::Deserialization(format!("JSON deserialization error: {}", e)))
    }

    /// Serialize to MsgPack
    fn serialize_msgpack(&self, val: &T) -> Result<Vec<u8>, KomerError> {
        rmp_serde::to_vec(val)
            .map_err(|e| KomerError::Serialization(format!("MsgPack serialization error: {}", e)))
    }

    /// Deserialize from MsgPack
    fn deserialize_msgpack(&self, val: &[u8]) -> Result<T, KomerError> {
        rmp_serde::from_slice(val).map_err(|e| {
            KomerError::Deserialization(format!("MsgPack deserialization error: {}", e))
        })
    }

    /// Serialize to CBOR
    fn serialize_cbor(&self, val: &T) -> Result<Vec<u8>, KomerError> {
        serde_cbor::to_vec(val)
            .map_err(|e| KomerError::Serialization(format!("CBOR serialization error: {}", e)))
    }

    /// Deserialize from CBOR
    fn deserialize_cbor(&self, val: &[u8]) -> Result<T, KomerError> {
        serde_cbor::from_slice(val)
            .map_err(|e| KomerError::Deserialization(format!("CBOR deserialization error: {}", e)))
    }

    /// Get an iterator over items with keys starting with the provided prefix
    pub fn get_item_iter<K>(&self, keys: &[K]) -> Result<Vec<(Vec<String>, T)>, KomerError>
    where
        K: AsRef<[u8]>,
    {
        // Convert keys to a single key for database prefix search
        let key_prefix = self.to_key(keys, false);

        // Create a prefix iterator
        let mut result = Vec::new();
        self.db
            .get_top_items_iter(&self.sdb, &key_prefix, |key, value| {
                let key_strings = self.to_keys(&key);
                let deserialized = self
                    .deserialize(&value)
                    .map_err(|_| DBError::ValueError("Failed to deserialize value".to_string()))?;
                result.push((key_strings, deserialized));
                Ok(true)
            })?;

        Ok(result)
    }

    /// Get full item iterator (same as get_item_iter in this implementation)
    pub fn get_full_item_iter<K>(&self, keys: &[K]) -> Result<Vec<(Vec<String>, T)>, KomerError>
    where
        K: AsRef<[u8]>,
    {
        self.get_item_iter(keys)
    }

    /// Put a value into the database with the given keys
    pub fn put<K>(&self, keys: &[K], val: &T) -> Result<bool, KomerError>
    where
        K: AsRef<[u8]>,
    {
        let key = self.to_key(keys, false);
        if key.is_empty() {
            Err(KomerError::EmptyKeys)
        } else {
            let value = self.serialize(val)?;
            Ok(self.db.put_val(&self.sdb, &key, &value)?)
        }
    }

    /// Get a value from the database with the given keys
    pub fn get<K>(&self, keys: &[K]) -> Result<Option<T>, KomerError>
    where
        K: AsRef<[u8]>,
    {
        let key = self.to_key(keys, false);
        if let Some(val) = self.db.get_val(&self.sdb, &key)? {
            Ok(Some(self.deserialize(&val)?))
        } else {
            Ok(None)
        }
    }

    /// Remove a value from the database with the given keys
    pub fn rem<K>(&self, keys: &[K]) -> Result<bool, KomerError>
    where
        K: AsRef<[u8]>,
    {
        let key = self.to_key(keys, false);
        let existed = self.db.del_val(&self.sdb, &key)?;
        Ok(existed)
    }

    /// Count all items in the database
    pub fn cnt_all(&self) -> Result<usize, KomerError> {
        Ok(self.db.len(&self.sdb)? as usize)
    }
}

/// Keyspace Object Mapper factory struct.
#[allow(dead_code)]
pub struct Komer<'db, T>
where
    T: Serialize + for<'de> Deserialize<'de> + Debug,
{
    base: KomerBase<'db, T>,
}

impl<'db, T> Komer<'db, T>
where
    T: Serialize + for<'de> Deserialize<'de> + Debug,
{
    /// Creates a new Komer instance.
    ///
    /// # Parameters
    /// * `db` - Base database reference
    /// * `subkey` - LMDB sub database key
    /// * `kind` - Serialization/deserialization type
    ///
    /// # Returns
    /// A Result containing the Komer instance or a KomerError
    pub fn new(db: Arc<&'db LMDBer>, subkey: &str, kind: SerialKind) -> Result<Self, KomerError> {
        let base = KomerBase::new(db, subkey, kind, false, None)?;

        Ok(Self { base })
    }

    /// Puts val at key made from keys. Does not overwrite.
    ///
    /// # Parameters
    /// * `txn` - Database transaction
    /// * `keys` - Key components to be combined to form the key
    /// * `val` - Value to store
    ///
    /// # Returns
    /// True if successful, False otherwise (e.g., if key already exists in database)
    pub fn put<K>(&self, keys: &[K], val: &T) -> Result<bool, KomerError>
    where
        K: AsRef<[u8]>,
    {
        self.base.put(keys, val)
    }

    /// Pins (sets) val at key made from keys. Overwrites existing value.
    ///
    /// # Parameters
    /// * `txn` - Database transaction
    /// * `keys` - Key components to be combined to form the key
    /// * `val` - Value to store
    ///
    /// # Returns
    /// True if successful, False otherwise
    pub fn pin<K>(&self, keys: &[K], val: &T) -> Result<bool, KomerError>
    where
        K: AsRef<[u8]>,
    {
        // Convert keys to a single key
        let key = self.base.to_key(keys, false);

        // Serialize value
        let serialized = self.base.serialize(val)?;

        // Set the value in the database (overwriting if it exists)
        match self.base.db.set_val(&self.base.sdb, &key, &serialized) {
            Ok(_) => Ok(true),
            Err(e) => Err(KomerError::DBError(e)),
        }
    }

    /// Gets val at keys.
    ///
    /// # Parameters
    /// * `txn` - Database transaction
    /// * `keys` - Key components to be combined to form the key
    ///
    /// # Returns
    /// Option containing the value if found, None if no entry at keys
    pub fn get<K>(&self, keys: &[K]) -> Result<Option<T>, KomerError>
    where
        K: AsRef<[u8]>,
    {
        self.base.get(keys)
    }

    /// Gets dictified val at keys.
    /// In Rust, we'll return a serde_json::Value instead of a dict.
    ///
    /// # Parameters
    /// * `txn` - Database transaction
    /// * `keys` - Key components to be combined to form the key
    ///
    /// # Returns
    /// Option containing the value as JSON if found, None if no entry at keys
    pub fn get_json<K>(&self, keys: &[K]) -> Result<Option<serde_json::Value>, KomerError>
    where
        K: AsRef<[u8]>,
    {
        if let Some(val) = self.get(keys)? {
            match serde_json::to_value(&val) {
                Ok(json_val) => Ok(Some(json_val)),
                Err(e) => Err(KomerError::Serialization(e.to_string())),
            }
        } else {
            Ok(None)
        }
    }

    pub fn get_item_iter<K>(&self, keys: &[K]) -> Result<Vec<(Vec<String>, T)>, KomerError>
    where
        K: AsRef<[u8]>,
    {
        self.base.get_item_iter(keys)
    }
    /// Removes entry at keys.
    ///
    /// # Parameters
    /// * `txn` - Database transaction
    /// * `keys` - Key components to be combined to form the key
    ///
    /// # Returns
    /// True if key exists so delete successful, False otherwise
    pub fn rem<K>(&self, keys: &[K]) -> Result<bool, KomerError>
    where
        K: AsRef<[u8]>,
    {
        self.base.rem(keys)
    }

    /// Removes all entries whose keys starts with the given keys prefix.
    /// Enables removal of whole branches of db key space.
    ///
    /// # Parameters
    /// * `txn` - Database transaction
    /// * `keys` - Key components to be combined to form the prefix
    ///
    /// # Returns
    /// True if operation successful, False otherwise
    pub fn trim<K>(&self, keys: &[K]) -> Result<bool, KomerError>
    where
        K: AsRef<[u8]>,
    {
        let key = self.base.to_key(keys, true);
        Ok(self.base.db.del_top_val(&self.base.sdb, &key)?)
    }

    /// Return the count of all items in the subdatabase.
    ///
    /// # Parameters
    ///
    /// # Returns
    /// Number of items in the database
    pub fn cnt_all(&self) -> Result<usize, KomerError> {
        self.base.cnt_all()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};
    use std::collections::HashMap;
    use std::fmt::Debug;
    use std::sync::Arc;

    #[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
    struct Record {
        first: String,  // first name
        last: String,   // last name
        street: String, // street address
        city: String,   // city name
        state: String,  // state code
        zip: u32,       // zip code
    }

    #[test]
    fn test_kom_happy_path() -> Result<(), Box<dyn std::error::Error>> {
        // Create and serialize a Record
        let jim = Record {
            first: "Jim".to_string(),
            last: "Black".to_string(),
            street: "100 Main Street".to_string(),
            city: "Riverton".to_string(),
            state: "UT".to_string(),
            zip: 84058,
        };

        let jimser = serde_json::to_string(&jim)?;
        let jim_deserialized: Record = serde_json::from_str(&jimser)?;
        assert_eq!(jim_deserialized, jim);

        // Open database
        let lmdber = LMDBer::builder().name("test_db").temp(true).build()?;
        let db_ref = Arc::new(&lmdber);

        // Create Komer instance
        let mydb = Komer::<Record>::new(db_ref.clone(), "records.", SerialKind::Json)?;

        // Check if dupsort is not enabled
        // assert!(!mydb.base.sdb.flags()?.dupsort);

        // Create a test record
        let sue = Record {
            first: "Susan".to_string(),
            last: "Black".to_string(),
            street: "100 Main Street".to_string(),
            city: "Riverton".to_string(),
            state: "UT".to_string(),
            zip: 84058,
        };

        // Test key handling
        let keys = ["test_key", "0001"];
        assert_eq!(mydb.base.sep, ".");

        // Test to_key and to_keys
        let key = mydb.base.to_key(&keys, false);
        let str = std::str::from_utf8(&key)?;
        assert_eq!(key, b"test_key.0001");
        assert_eq!(
            mydb.base.to_keys(&key),
            vec!["test_key".to_string(), "0001".to_string()]
        );

        // Test put and get
        mydb.put(&keys, &sue)?;
        let actual = mydb.get(&keys)?.unwrap();

        assert_eq!(actual.first, "Susan");
        assert_eq!(actual.last, "Black");
        assert_eq!(actual.street, "100 Main Street");
        assert_eq!(actual.city, "Riverton");
        assert_eq!(actual.state, "UT");
        assert_eq!(actual.zip, 84058);

        // Test rem
        mydb.rem(&keys)?;
        let actual = mydb.get(&keys)?;
        assert!(actual.is_none());

        // Test put and equality
        let keys = ["test_key", "0001"];
        mydb.put(&keys, &sue)?;
        let actual = mydb.get(&keys)?.unwrap();
        assert_eq!(actual, sue);

        // Test put with existing key (should not update)
        let kip = Record {
            first: "Kip".to_string(),
            last: "Thorne".to_string(),
            street: "200 Center Street".to_string(),
            city: "Bluffdale".to_string(),
            state: "UT".to_string(),
            zip: 84043,
        };

        let result = mydb.put(&keys, &kip)?;
        assert!(!result);
        let actual = mydb.get(&keys)?.unwrap();
        assert_eq!(actual, sue);

        // Test get_json
        let actual_json = mydb.get_json(&keys)?.unwrap();
        let expected_json = serde_json::to_value(&sue)?;
        assert_eq!(actual_json, expected_json);

        // Test pin (forced update)
        let result = mydb.pin(&keys, &kip)?;
        assert!(result);
        let actual = mydb.get(&keys)?.unwrap();
        assert_eq!(actual, kip);

        // Test with single string key instead of slice
        let keys = ["keystr"];

        let bob = Record {
            first: "Bob".to_string(),
            last: "Brown".to_string(),
            street: "100 Center Street".to_string(),
            city: "Bluffdale".to_string(),
            state: "UT".to_string(),
            zip: 84043,
        };

        mydb.put(&keys, &bob)?;
        let actual = mydb.get(&keys)?.unwrap();

        assert_eq!(actual.first, "Bob");
        assert_eq!(actual.last, "Brown");
        assert_eq!(actual.street, "100 Center Street");
        assert_eq!(actual.city, "Bluffdale");
        assert_eq!(actual.state, "UT");
        assert_eq!(actual.zip, 84043);

        // Test get_json
        let actual_json = mydb.get_json(&keys)?.unwrap();
        let expected_json = serde_json::to_value(&bob)?;
        assert_eq!(actual_json, expected_json);

        // Test empty keys
        let nonexistent_keys = ["bla", "bal"];
        assert!(mydb.get_json(&nonexistent_keys)?.is_none());

        // Test rem
        mydb.rem(&keys)?;
        let actual = mydb.get(&keys)?;
        assert!(actual.is_none());

        // Close the database (will happen when db goes out of scope)
        drop(lmdber);

        // Temporary directory should be removed when temp_dir goes out of scope
        Ok(())
    }

    #[test]
    fn test_komer_error_handling() -> Result<(), Box<dyn std::error::Error>> {
        // Open database
        let lmdber = LMDBer::builder().name("test_db").temp(true).build()?;
        let db_ref = Arc::new(&lmdber);

        // Test empty keys
        let mydb = Komer::<Record>::new(db_ref.clone(), "records.", SerialKind::Json)?;

        let empty_keys: [&str; 0] = [];
        let record = Record {
            first: "Test".to_string(),
            last: "User".to_string(),
            street: "123 Test St".to_string(),
            city: "Testville".to_string(),
            state: "TS".to_string(),
            zip: 12345,
        };

        // This should return an EmptyKeys error
        let result = mydb.put(&empty_keys, &record);
        assert!(matches!(result, Err(KomerError::EmptyKeys)));

        Ok(())
    }

    #[test]
    fn test_serialization_formats() -> Result<(), Box<dyn std::error::Error>> {
        // Open database
        let lmdber = LMDBer::builder().name("test_db").temp(true).build()?;
        let db_ref = Arc::new(&lmdber);

        // Test record
        let record = Record {
            first: "Test".to_string(),
            last: "User".to_string(),
            street: "123 Test St".to_string(),
            city: "Testville".to_string(),
            state: "TS".to_string(),
            zip: 12345,
        };

        // Test with different serialization formats
        for serial_kind in [SerialKind::Json, SerialKind::MsgPack, SerialKind::Cbor] {
            let mydb = Komer::<Record>::new(
                db_ref.clone(),
                &format!("records_{:?}.", serial_kind),
                serial_kind,
            )?;

            let keys = ["test_key"];
            mydb.put(&keys, &record)?;
            let retrieved = mydb.get(&keys)?.unwrap();

            assert_eq!(retrieved, record);
        }

        Ok(())
    }

    #[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
    struct Stuff {
        a: String,
        b: String,
    }

    impl Stuff {
        // Similar to Python's __iter__ that returns an iterator over asdict(self)
        pub fn to_map(&self) -> HashMap<String, String> {
            let mut map = HashMap::new();
            map.insert("a".to_string(), self.a.clone());
            map.insert("b".to_string(), self.b.clone());
            map
        }
    }

    #[test]
    fn test_kom_get_item_iter() -> Result<(), Box<dyn std::error::Error>> {
        // Test data setup
        let w = Stuff {
            a: "Big".to_string(),
            b: "Blue".to_string(),
        };
        let x = Stuff {
            a: "Tall".to_string(),
            b: "Red".to_string(),
        };
        let y = Stuff {
            a: "Fat".to_string(),
            b: "Green".to_string(),
        };
        let z = Stuff {
            a: "Eat".to_string(),
            b: "White".to_string(),
        };

        // Open test database
        let lmdber = LMDBer::builder().name("test").temp(true).build()?;

        let db_ref = Arc::new(&lmdber);
        assert_eq!(lmdber.name(), "test");
        assert!(lmdber.opened());

        // Create Komer instance
        let mydb = Komer::<Stuff>::new(db_ref.clone(), "recs.", SerialKind::Json)?;

        // Add initial data
        mydb.put(&["a", "1"], &w)?;
        mydb.put(&["a", "2"], &x)?;
        mydb.put(&["a", "3"], &y)?;
        mydb.put(&["a", "4"], &z)?;

        // Test iteration with getItemIter
        let items: Vec<(Vec<String>, HashMap<String, String>)> = mydb
            .get_item_iter(&[] as &[&str])?
            .into_iter()
            .map(|(keys, data)| (keys, data.to_map()))
            .collect();

        assert_eq!(
            items,
            vec![
                (vec!["a".to_string(), "1".to_string()], w.to_map()),
                (vec!["a".to_string(), "2".to_string()], x.to_map()),
                (vec!["a".to_string(), "3".to_string()], y.to_map()),
                (vec!["a".to_string(), "4".to_string()], z.to_map()),
            ]
        );

        // Add more data
        mydb.put(&["b", "1"], &w)?;
        mydb.put(&["b", "2"], &x)?;
        mydb.put(&["bc", "3"], &y)?;
        mydb.put(&["bc", "4"], &z)?;

        // Test iteration with specific top-level keys
        let topkeys = ["b", ""];
        let items: Vec<(Vec<String>, HashMap<String, String>)> = mydb
            .get_item_iter(&topkeys)?
            .into_iter()
            .map(|(keys, data)| (keys, data.to_map()))
            .collect();

        assert_eq!(
            items,
            vec![
                (vec!["b".to_string(), "1".to_string()], w.to_map()),
                (vec!["b".to_string(), "2".to_string()], x.to_map()),
            ]
        );

        // Test full iteration
        let items: Vec<(Vec<String>, HashMap<String, String>)> = mydb
            .get_item_iter(&[] as &[&str])?
            .into_iter()
            .map(|(keys, data)| (keys, data.to_map()))
            .collect();

        assert_eq!(
            items,
            vec![
                (vec!["a".to_string(), "1".to_string()], w.to_map()),
                (vec!["a".to_string(), "2".to_string()], x.to_map()),
                (vec!["a".to_string(), "3".to_string()], y.to_map()),
                (vec!["a".to_string(), "4".to_string()], z.to_map()),
                (vec!["b".to_string(), "1".to_string()], w.to_map()),
                (vec!["b".to_string(), "2".to_string()], x.to_map()),
                (vec!["bc".to_string(), "3".to_string()], y.to_map()),
                (vec!["bc".to_string(), "4".to_string()], z.to_map()),
            ]
        );

        // Test count all entries
        assert_eq!(mydb.cnt_all()?, 8);

        // Test trim by b prefix
        assert!(mydb.trim(&["b", ""])?);

        let items: Vec<(Vec<String>, HashMap<String, String>)> = mydb
            .get_item_iter(&[] as &[&str])?
            .into_iter()
            .map(|(keys, data)| (keys, data.to_map()))
            .collect();

        assert_eq!(
            items,
            vec![
                (vec!["a".to_string(), "1".to_string()], w.to_map()),
                (vec!["a".to_string(), "2".to_string()], x.to_map()),
                (vec!["a".to_string(), "3".to_string()], y.to_map()),
                (vec!["a".to_string(), "4".to_string()], z.to_map()),
                (vec!["bc".to_string(), "3".to_string()], y.to_map()),
                (vec!["bc".to_string(), "4".to_string()], z.to_map()),
            ]
        );

        // Test trim all
        assert!(mydb.trim::<[u8; 0]>(&[])?);

        let items: Vec<(Vec<String>, Stuff)> = mydb.get_item_iter(&[] as &[&str])?;

        assert_eq!(items, vec![]);

        // Drop database
        drop(lmdber);

        // Check database is closed and files are removed
        // No need to check manually as it's handled by the LMDBer drop implementation

        Ok(())
    }

    #[test]
    fn test_kom_put_get() -> Result<(), Box<dyn std::error::Error>> {
        // Open test database
        let lmdber = LMDBer::builder().name("test").temp(true).build()?;

        let db_ref = Arc::new(&lmdber);

        // Create Komer instance
        let mydb = Komer::<Stuff>::new(db_ref.clone(), "recs.", SerialKind::Json)?;

        let data = Stuff {
            a: "Test".to_string(),
            b: "Value".to_string(),
        };

        // Put data
        assert!(mydb.put(&["test", "key"], &data)?);

        // Get data
        let retrieved = mydb.get(&["test", "key"])?.unwrap();
        assert_eq!(retrieved, data);

        // Verify non-existent key returns None
        assert!(mydb.get(&["nonexistent", "key"])?.is_none());

        // Test duplicate put (shouldn't overwrite)
        let new_data = Stuff {
            a: "Modified".to_string(),
            b: "Data".to_string(),
        };

        assert!(!mydb.put(&["test", "key"], &new_data)?);

        // Verify original data wasn't changed
        let retrieved = mydb.get(&["test", "key"])?.unwrap();
        assert_eq!(retrieved, data);

        // Test pin (should overwrite)
        assert!(mydb.pin(&["test", "key"], &new_data)?);

        // Verify data was changed
        let retrieved = mydb.get(&["test", "key"])?.unwrap();
        assert_eq!(retrieved, new_data);

        // Test removal
        assert!(mydb.rem(&["test", "key"])?);
        assert!(mydb.get(&["test", "key"])?.is_none());

        // Test removal of non-existent key
        assert!(!mydb.rem(&["test", "key"])?);

        Ok(())
    }

    #[test]
    fn test_kom_serialization_formats() -> Result<(), Box<dyn std::error::Error>> {
        // Open test database
        let lmdber = LMDBer::builder().name("test").temp(true).build()?;

        let db_ref = Arc::new(&lmdber);

        let test_data = Stuff {
            a: "Test".to_string(),
            b: "Value".to_string(),
        };

        // Test all serialization formats
        for format in [SerialKind::Json, SerialKind::MsgPack, SerialKind::Cbor].iter() {
            let db_name = format!("test_{:?}", format);
            let mydb = Komer::<Stuff>::new(db_ref.clone(), &db_name, *format)?;

            // Put and get data
            mydb.put(&["test"], &test_data)?;
            let retrieved = mydb.get(&["test"])?.unwrap();

            assert_eq!(retrieved, test_data);
        }

        Ok(())
    }

    #[test]
    fn test_kom_empty_keys() -> Result<(), Box<dyn std::error::Error>> {
        // Open test database
        let lmdber = LMDBer::builder().name("test").temp(true).build()?;

        let db_ref = Arc::new(&lmdber);

        // Create Komer instance
        let mydb = Komer::<Stuff>::new(db_ref.clone(), "recs.", SerialKind::Json)?;

        let data = Stuff {
            a: "Test".to_string(),
            b: "Value".to_string(),
        };

        // Test with empty keys slice
        let empty_keys: [&str; 0] = [];
        let result = mydb.put(&empty_keys, &data);

        assert!(matches!(result, Err(KomerError::EmptyKeys)));

        Ok(())
    }
}
