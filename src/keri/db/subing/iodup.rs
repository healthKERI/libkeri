use crate::keri::db::dbing::{BytesDatabase, LMDBer};
use crate::keri::db::subing::dup::DupSuber;
use crate::keri::db::subing::{SuberError, Utf8Codec, ValueCodec};
use std::marker::PhantomData;
use std::sync::Arc;

/// IoDupSuber - Sub class of DupSuber that supports Insertion Ordering (IoDup) of duplicates
///
/// By automagically prepending and stripping ordinal proem to/from each
/// duplicate value at a given key.
///
/// IoDupSuber supports insertion ordered multiple entries at each key
/// (duplicates) with dupsort==True
///
/// Do not use if serialized length key + proem + value, is greater than 511 bytes.
/// This is a limitation of dupsort==True sub dbs in LMDB
///
/// IoDupSuber may be more performant then IoSetSuber for values that are indices
/// to other sub dbs that fit the size constraint because LMDB support for
/// duplicates is more space efficient and code performant.
///
/// Duplicates at a given key preserve insertion order of duplicate.
/// Because lmdb is lexocographic an insertion ordering proem is prepended to
/// all values that makes lexocographic order that same as insertion order.
///
/// Duplicates are ordered as a pair of key plus value so prepending proem
/// to each value changes duplicate ordering. Proem is 33 characters long.
/// With 32 character hex string followed by '.' for essentially unlimited
/// number of values which will be limited by memory.
///
/// With prepended proem ordinal must explicitly check for duplicate values
/// before insertion. Uses a set for the duplicate inclusion test.
pub struct IoDupSuber<'db, C: ValueCodec = Utf8Codec> {
    base: DupSuber<'db, C>,
}

impl<'db, C: ValueCodec> IoDupSuber<'db, C> {
    /// Creates a new `IoDupSuber` instance.
    pub fn new(
        db: Arc<&'db LMDBer>,
        subkey: &str,
        sep: Option<u8>,
        verify: bool,
    ) -> Result<Self, SuberError> {
        let base = DupSuber::new(db, subkey, sep, verify)?;

        Ok(Self { base })
    }

    /// Puts all vals idempotently at key made from keys in insertion order using
    /// hidden ordinal proem. Idempotently means do not put any val in vals that is
    /// already in dup vals at key. Does not overwrite.
    ///
    /// # Arguments
    /// * `keys` - Slice of key parts to be combined to form the key
    /// * `vals` - Slice of values to be stored
    ///
    /// # Returns
    /// * `Result<bool, SuberError>` - True if successful, otherwise an error
    pub fn put<K: AsRef<[u8]>, V: ?Sized + Clone + Into<Vec<u8>>>(
        &self,
        keys: &[K],
        vals: &[&V],
    ) -> Result<bool, SuberError> {
        let key = self.base.base.to_key(keys, false);

        // Serialize all values
        let serialized_vals: Vec<Vec<u8>> = vals
            .iter()
            .map(|v| self.base.base.ser(*v))
            .collect::<Result<Vec<Vec<u8>>, _>>()?;

        // Create Vec<&[u8]> by borrowing from serialized_vals
        let val_slices: Vec<&[u8]> = serialized_vals.iter().map(|v| v.as_slice()).collect();

        // Use the put_io_dup_vals method for insertion ordered duplicates
        self.base
            .base
            .db
            .put_io_dup_vals(&self.base.base.sdb, &key, &val_slices)
            .map_err(SuberError::DBError)
    }

    /// Add val idempotently at key made from keys in insertion order using hidden
    /// ordinal proem. Idempotently means do not add val that is already in
    /// dup vals at key. Does not overwrite.
    ///
    /// # Arguments
    /// * `keys` - Slice of key parts to be combined to form the key
    /// * `val` - Value to be stored
    ///
    /// # Returns
    /// * `Result<bool, SuberError>` - True means unique value added among duplications,
    ///   False means duplicate of same value already exists.
    pub fn add<K: AsRef<[u8]>, V: ?Sized + Clone + Into<Vec<u8>>>(
        &self,
        keys: &[K],
        val: &V,
    ) -> Result<bool, SuberError> {
        let key = self.base.base.to_key(keys, false);
        let sval = self.base.base.ser(val)?;

        self.base
            .base
            .db
            .add_io_dup_val(&self.base.base.sdb, &key, &sval)
            .map_err(SuberError::DBError)
    }

    /// Pins (sets) vals at key made from keys in insertion order using hidden
    /// ordinal proem. Overwrites. Removes all pre-existing vals that share
    /// same keys and replaces them with vals
    ///
    /// # Arguments
    /// * `keys` - Slice of key parts to be combined to form the key
    /// * `vals` - Slice of values to be stored
    ///
    /// # Returns
    /// * `Result<bool, SuberError>` - True if successful, otherwise an error
    pub fn pin<K: AsRef<[u8]>, V: ?Sized + Clone + Into<Vec<u8>>>(
        &self,
        keys: &[K],
        vals: &[&V],
    ) -> Result<bool, SuberError> {
        let key = self.base.base.to_key(keys, false);

        // Delete all values at the key first
        self.base
            .base
            .db
            .del_io_dup_vals(&self.base.base.sdb, &key)
            .map_err(SuberError::DBError)?;

        // If there are no values to add, return true (successful operation)
        if vals.is_empty() {
            return Ok(true);
        }

        // Serialize all values
        let serialized_vals: Vec<Vec<u8>> = vals
            .iter()
            .map(|v| self.base.base.ser(*v))
            .collect::<Result<Vec<Vec<u8>>, _>>()?;

        // Create Vec<&[u8]> by borrowing from serialized_vals
        let val_slices: Vec<&[u8]> = serialized_vals.iter().map(|v| v.as_slice()).collect();

        // Add the new values
        self.base
            .base
            .db
            .put_io_dup_vals(&self.base.base.sdb, &key, &val_slices)
            .map_err(SuberError::DBError)
    }

    /// Gets vals dup list in insertion order using key made from keys and
    /// hidden ordinal proem on dups.
    ///
    /// # Arguments
    /// * `keys` - Slice of key parts to be combined to form the key
    ///
    /// # Returns
    /// * `Result<Vec<R>, SuberError>` - Vector of deserialized values, empty if none found
    pub fn get<K: AsRef<[u8]>, R: TryFrom<Vec<u8>>>(&self, keys: &[K]) -> Result<Vec<R>, SuberError>
    where
        <R as TryFrom<Vec<u8>>>::Error: std::fmt::Debug,
    {
        let key = self.base.base.to_key(keys, false);
        let values = self
            .base
            .base
            .db
            .get_io_dup_vals(&self.base.base.sdb, &key)
            .map_err(SuberError::DBError)?;

        values.iter().map(|val| self.base.base.des(val)).collect()
    }

    /// Gets vals dup iterator in insertion order using key made from keys and
    /// hidden ordinal proem on dups.
    /// All vals in dups that share same key are retrieved in insertion order.
    ///
    /// # Arguments
    /// * `keys` - Slice of key parts to be combined to form the key
    ///
    /// # Returns
    /// * `Result<impl Iterator<Item = Result<R, SuberError>>, SuberError>` - Iterator of results
    pub fn get_iter<K: AsRef<[u8]>, R: TryFrom<Vec<u8>> + 'static>(
        &self,
        keys: &[K],
    ) -> Result<impl Iterator<Item = Result<R, SuberError>>, SuberError>
    where
        <R as TryFrom<Vec<u8>>>::Error: std::fmt::Debug,
        SuberError: From<<R as TryFrom<Vec<u8>>>::Error>,
    {
        let key = self.base.base.to_key(keys, false);
        let mut results: Vec<Result<R, SuberError>> = Vec::new();

        self.base
            .base
            .db
            .get_io_dup_vals_iter(&self.base.base.sdb, &key, |val| {
                let result = self.base.base.des(val);
                results.push(result);
                Ok(true)
            })
            .map_err(SuberError::DBError)?;

        Ok(results.into_iter())
    }

    /// Gets last val inserted at key made from keys in insertion order using
    /// hidden ordinal proem.
    ///
    /// # Arguments
    /// * `keys` - Slice of key parts to be combined to form the key
    ///
    /// # Returns
    /// * `Result<Option<R>, SuberError>` - The last value if found, None otherwise
    pub fn get_last<K: AsRef<[u8]>, R: TryFrom<Vec<u8>>>(
        &self,
        keys: &[K],
    ) -> Result<Option<R>, SuberError>
    where
        <R as TryFrom<Vec<u8>>>::Error: std::fmt::Debug,
    {
        let key = self.base.base.to_key(keys, false);
        let raw_val_opt = self
            .base
            .base
            .db
            .get_io_dup_val_last(&self.base.base.sdb, &key)
            .map_err(SuberError::DBError)?;

        match raw_val_opt {
            Some(val) => self.base.base.des(&val).map(Some),
            None => Ok(None),
        }
    }

    /// Removes entry at key made from keys and dup val that matches val if any,
    /// notwithstanding hidden ordinal proem. Otherwise deletes all dup values
    /// at key if val is None.
    ///
    /// # Arguments
    /// * `keys` - Slice of key parts to be combined to form the key
    /// * `val` - Optional value to remove; if None, removes all values at the key
    ///
    /// # Returns
    /// * `Result<bool, SuberError>` - True if successful, False otherwise
    pub fn rem<K: AsRef<[u8]>, V: ?Sized + Clone + Into<Vec<u8>>>(
        &self,
        keys: &[K],
        val: Option<&V>,
    ) -> Result<bool, SuberError> {
        let key = self.base.base.to_key(keys, false);

        match val {
            Some(v) => {
                let sval = self.base.base.ser(v)?;
                self.base
                    .base
                    .db
                    .del_io_dup_val(&self.base.base.sdb, &key, &sval)
                    .map_err(SuberError::DBError)
            }
            None => self
                .base
                .base
                .db
                .del_io_dup_vals(&self.base.base.sdb, &key)
                .map_err(SuberError::DBError),
        }
    }

    /// Return count of dup values at key made from keys with hidden ordinal
    /// proem. Zero otherwise
    ///
    /// # Arguments
    /// * `keys` - Slice of key parts to be combined to form the key
    ///
    /// # Returns
    /// * `Result<usize, SuberError>` - Count of values
    pub fn cnt<K: AsRef<[u8]>>(&self, keys: &[K]) -> Result<usize, SuberError> {
        let key = self.base.base.to_key(keys, false);
        self.base
            .base
            .db
            .cnt_io_dup_vals(&self.base.base.sdb, &key)
            .map_err(SuberError::DBError)
    }

    /// Return iterator over all the items including dup items for all keys
    /// in top branch defined by keys where keys may be truncation of full branch.
    ///
    /// # Arguments
    /// * `keys` - Slice of key parts, potentially a partial key
    /// * `topive` - If true, treat as partial key tuple ending with separator
    ///
    /// # Returns
    /// * `Result<Vec<(Vec<Vec<u8>>, Vec<u8>)>, SuberError>` - Vector of key-value pairs
    pub fn get_item_iter<K: AsRef<[u8]>>(
        &self,
        keys: &[K],
        topive: bool,
    ) -> Result<Vec<(Vec<Vec<u8>>, Vec<u8>)>, SuberError> {
        let key = self.base.base.to_key(keys, topive);

        let mut result = Vec::new();
        self.base
            .base
            .db
            .get_top_io_dup_item_iter(&self.base.base.sdb, &key, |k, v| {
                result.push((self.base.base.to_keys(k), v.to_vec()));
                Ok(true)
            })
            .map_err(SuberError::DBError)?;

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keri::db::dbing::LMDBer;
    use std::sync::Arc;

    // Helper function to convert keys and value to string representation
    fn key_val_to_string(key_val: &(Vec<Vec<u8>>, Vec<u8>)) -> (Vec<String>, String) {
        let (keys, val) = key_val;
        let string_keys = keys
            .iter()
            .map(|k| String::from_utf8(k.clone()).unwrap())
            .collect();
        let string_val = String::from_utf8(val.clone()).unwrap();
        (string_keys, string_val)
    }

    // Helper function to convert items to string tuples for easier assertions
    fn items_to_string_tuples(items: &[(Vec<Vec<u8>>, Vec<u8>)]) -> Vec<(Vec<String>, String)> {
        items.iter().map(key_val_to_string).collect()
    }

    #[test]
    fn test_io_dup_suber() -> Result<(), SuberError> {
        // Create a temporary database for the test
        let lmdber = LMDBer::builder().name("test").temp(true).build()?;

        assert_eq!(lmdber.name(), "test");
        assert!(lmdber.opened());

        // Create IoDupSuber
        let ioduber: IoDupSuber<Utf8Codec> =
            IoDupSuber::new(Arc::new(&lmdber), "bags.", None, false)?;
        assert!(ioduber.base.is_dupsort());

        // Test data
        let sue = "Hello sailer!";
        let sal = "Not my type.";

        let keys0 = &["test_key", "0001"];
        let keys1 = &["test_key", "0002"];

        // Test put and get methods with string conversion for direct comparison
        assert!(ioduber.put(keys0, &[&sal, &sue])?);
        let bytes: Vec<Vec<u8>> = ioduber.get(keys0)?;
        let actuals: Vec<String> = bytes
            .into_iter()
            .map(|b| String::from_utf8(b).unwrap())
            .collect();
        assert_eq!(actuals, vec![sal.to_string(), sue.to_string()]); // insertion order not lexicographic
        assert_eq!(ioduber.cnt(keys0)?, 2);

        // Test getLast method
        let last_bytes: Option<Vec<u8>> = ioduber.get_last(keys0)?;
        let actual = last_bytes.map(|b| String::from_utf8(b).unwrap());
        assert_eq!(actual, Some(sue.to_string()));

        // Test remove method
        assert!(ioduber.rem(keys0, None::<&String>)?);
        let bytes: Vec<Vec<u8>> = ioduber.get(keys0)?;
        let actuals: Vec<String> = bytes
            .into_iter()
            .map(|b| String::from_utf8(b).unwrap())
            .collect();
        assert!(actuals.is_empty());
        assert_eq!(actuals, Vec::<String>::new());
        assert_eq!(ioduber.cnt(keys0)?, 0);

        // Test put and get again
        assert!(ioduber.put(keys0, &[&sue, &sal])?);
        let bytes: Vec<Vec<u8>> = ioduber.get(keys0)?;
        let actuals: Vec<String> = bytes
            .into_iter()
            .map(|b| String::from_utf8(b).unwrap())
            .collect();
        assert_eq!(actuals, vec![sue.to_string(), sal.to_string()]); // insertion order

        let last_bytes: Option<Vec<u8>> = ioduber.get_last(keys0)?;
        let actual = last_bytes.map(|b| String::from_utf8(b).unwrap());
        assert_eq!(actual, Some(sal.to_string()));

        // Test add method
        let sam = "A real charmer!";
        let result = ioduber.add(keys0, &sam)?;
        assert!(result);
        let bytes: Vec<Vec<u8>> = ioduber.get(keys0)?;
        let actuals: Vec<String> = bytes
            .into_iter()
            .map(|b| String::from_utf8(b).unwrap())
            .collect();
        assert_eq!(
            actuals,
            vec![sue.to_string(), sal.to_string(), sam.to_string()]
        ); // insertion order

        // Test pin method
        let zoe = "See ya later.";
        let zia = "Hey gorgeous!";
        let result = ioduber.pin(keys0, &[&zoe, &zia])?;
        assert!(result);
        let bytes: Vec<Vec<u8>> = ioduber.get(keys0)?;
        let actuals: Vec<String> = bytes
            .into_iter()
            .map(|b| String::from_utf8(b).unwrap())
            .collect();
        assert_eq!(actuals, vec![zoe.to_string(), zia.to_string()]); // insertion order

        // Test with multiple keys
        assert!(ioduber.put(keys1, &[&sal, &sue, &sam])?);
        let bytes: Vec<Vec<u8>> = ioduber.get(keys1)?;
        let actuals: Vec<String> = bytes
            .into_iter()
            .map(|b| String::from_utf8(b).unwrap())
            .collect();
        assert_eq!(
            actuals,
            vec![sal.to_string(), sue.to_string(), sam.to_string()]
        );

        // Test getIter - equivalent to Python's getIter
        let mut i = 0;
        for val_result in ioduber.get_iter::<_, Vec<u8>>(keys1)? {
            let val = String::from_utf8(val_result?).unwrap();
            assert_eq!(val, actuals[i]);
            i += 1;
        }

        // Test getItemIter - equivalent to Python's getItemIter
        let empty_key: &[&str] = &[];
        let items = ioduber.get_item_iter(empty_key, false)?;
        let string_items = items_to_string_tuples(&items);

        // Direct assertion of expected key-value structures
        assert_eq!(
            string_items,
            vec![
                (
                    vec!["test_key".to_string(), "0001".to_string()],
                    "See ya later.".to_string()
                ),
                (
                    vec!["test_key".to_string(), "0001".to_string()],
                    "Hey gorgeous!".to_string()
                ),
                (
                    vec!["test_key".to_string(), "0002".to_string()],
                    "Not my type.".to_string()
                ),
                (
                    vec!["test_key".to_string(), "0002".to_string()],
                    "Hello sailer!".to_string()
                ),
                (
                    vec!["test_key".to_string(), "0002".to_string()],
                    "A real charmer!".to_string()
                ),
            ]
        );

        // Test getFullItemIter - equivalent to Python's getFullItemIter
        let items = ioduber.base.base.get_full_item_iter(empty_key, false)?;
        let string_items = items_to_string_tuples(&items);

        // Check full items with proem
        assert_eq!(
            string_items,
            vec![
                (
                    vec!["test_key".to_string(), "0001".to_string()],
                    "00000000000000000000000000000000.See ya later.".to_string()
                ),
                (
                    vec!["test_key".to_string(), "0001".to_string()],
                    "00000000000000000000000000000001.Hey gorgeous!".to_string()
                ),
                (
                    vec!["test_key".to_string(), "0002".to_string()],
                    "00000000000000000000000000000000.Not my type.".to_string()
                ),
                (
                    vec!["test_key".to_string(), "0002".to_string()],
                    "00000000000000000000000000000001.Hello sailer!".to_string()
                ),
                (
                    vec!["test_key".to_string(), "0002".to_string()],
                    "00000000000000000000000000000002.A real charmer!".to_string()
                ),
            ]
        );

        // Test getItemIter with specific keys = keys1
        let items = ioduber.get_item_iter(keys1, false)?;
        let string_items = items_to_string_tuples(&items);

        assert_eq!(
            string_items,
            vec![
                (
                    vec!["test_key".to_string(), "0002".to_string()],
                    "Not my type.".to_string()
                ),
                (
                    vec!["test_key".to_string(), "0002".to_string()],
                    "Hello sailer!".to_string()
                ),
                (
                    vec!["test_key".to_string(), "0002".to_string()],
                    "A real charmer!".to_string()
                ),
            ]
        );

        // Test getItemIter with specific keys = keys0
        let items = ioduber.get_item_iter(keys0, false)?;
        let string_items = items_to_string_tuples(&items);

        assert_eq!(
            string_items,
            vec![
                (
                    vec!["test_key".to_string(), "0001".to_string()],
                    "See ya later.".to_string()
                ),
                (
                    vec!["test_key".to_string(), "0001".to_string()],
                    "Hey gorgeous!".to_string()
                ),
            ]
        );

        // Test with top keys
        let test_pop = &["test", "pop"];
        assert!(ioduber.put(test_pop, &[&sal, &sue, &sam])?);
        let topkeys = &["test", ""];
        let items = ioduber.get_item_iter(topkeys, false)?;
        let string_items = items_to_string_tuples(&items);

        assert_eq!(
            string_items,
            vec![
                (
                    vec!["test".to_string(), "pop".to_string()],
                    "Not my type.".to_string()
                ),
                (
                    vec!["test".to_string(), "pop".to_string()],
                    "Hello sailer!".to_string()
                ),
                (
                    vec!["test".to_string(), "pop".to_string()],
                    "A real charmer!".to_string()
                ),
            ]
        );

        // Test with top parameter
        let keys = &["test"];
        let items = ioduber.get_item_iter(keys, true)?;
        let string_items = items_to_string_tuples(&items);

        assert_eq!(
            string_items,
            vec![
                (
                    vec!["test".to_string(), "pop".to_string()],
                    "Not my type.".to_string()
                ),
                (
                    vec!["test".to_string(), "pop".to_string()],
                    "Hello sailer!".to_string()
                ),
                (
                    vec!["test".to_string(), "pop".to_string()],
                    "A real charmer!".to_string()
                ),
            ]
        );

        // Test IoItems (getFullItemIter with keys)
        let items = ioduber.base.base.get_full_item_iter(topkeys, false)?;
        let string_items = items_to_string_tuples(&items);

        assert_eq!(
            string_items,
            vec![
                (
                    vec!["test".to_string(), "pop".to_string()],
                    "00000000000000000000000000000000.Not my type.".to_string()
                ),
                (
                    vec!["test".to_string(), "pop".to_string()],
                    "00000000000000000000000000000001.Hello sailer!".to_string()
                ),
                (
                    vec!["test".to_string(), "pop".to_string()],
                    "00000000000000000000000000000002.A real charmer!".to_string()
                ),
            ]
        );

        // Test remove with a specific val
        assert!(ioduber.rem(keys1, Some(&sue))?);

        // Sequence of state validation after remove operation
        let items = ioduber.get_item_iter(empty_key, false)?;
        let string_items = items_to_string_tuples(&items);

        assert_eq!(
            string_items,
            vec![
                (
                    vec!["test".to_string(), "pop".to_string()],
                    "Not my type.".to_string()
                ),
                (
                    vec!["test".to_string(), "pop".to_string()],
                    "Hello sailer!".to_string()
                ),
                (
                    vec!["test".to_string(), "pop".to_string()],
                    "A real charmer!".to_string()
                ),
                (
                    vec!["test_key".to_string(), "0001".to_string()],
                    "See ya later.".to_string()
                ),
                (
                    vec!["test_key".to_string(), "0001".to_string()],
                    "Hey gorgeous!".to_string()
                ),
                (
                    vec!["test_key".to_string(), "0002".to_string()],
                    "Not my type.".to_string()
                ),
                (
                    vec!["test_key".to_string(), "0002".to_string()],
                    "A real charmer!".to_string()
                ),
            ]
        );

        // Test trim with specific keys
        assert!(ioduber.base.base.trim(topkeys, false)?);

        // Sequence of state validation after trim operation
        let items = ioduber.get_item_iter(empty_key, false)?;
        let string_items = items_to_string_tuples(&items);

        assert_eq!(
            string_items,
            vec![
                (
                    vec!["test_key".to_string(), "0001".to_string()],
                    "See ya later.".to_string()
                ),
                (
                    vec!["test_key".to_string(), "0001".to_string()],
                    "Hey gorgeous!".to_string()
                ),
                (
                    vec!["test_key".to_string(), "0002".to_string()],
                    "Not my type.".to_string()
                ),
                (
                    vec!["test_key".to_string(), "0002".to_string()],
                    "A real charmer!".to_string()
                ),
            ]
        );

        assert_eq!(ioduber.cnt(keys0)?, 2);
        assert_eq!(ioduber.cnt(keys1)?, 2);

        // Test with keys as string not tuple
        let keys2 = &["keystr"];
        let bob = "Shove off!";
        assert!(ioduber.put(keys2, &[&bob])?);
        let bytes: Vec<Vec<u8>> = ioduber.get(keys2)?;
        let actuals: Vec<String> = bytes
            .into_iter()
            .map(|b| String::from_utf8(b).unwrap())
            .collect();
        assert_eq!(actuals, vec![bob.to_string()]);
        assert_eq!(ioduber.cnt(keys2)?, 1);

        assert!(ioduber.rem(keys2, None::<&String>)?);
        let bytes: Vec<Vec<u8>> = ioduber.get(keys2)?;
        let actuals: Vec<String> = bytes
            .into_iter()
            .map(|b| String::from_utf8(b).unwrap())
            .collect();
        assert!(actuals.is_empty());
        assert_eq!(ioduber.cnt(keys2)?, 0);

        assert!(ioduber.put(keys2, &[&bob])?);
        let bytes: Vec<Vec<u8>> = ioduber.get(keys2)?;
        let actuals: Vec<String> = bytes
            .into_iter()
            .map(|b| String::from_utf8(b).unwrap())
            .collect();
        assert_eq!(actuals, vec![bob.to_string()]);

        let bil = "Go away.";
        assert!(ioduber.pin(keys2, &[&bil])?);
        let bytes: Vec<Vec<u8>> = ioduber.get(keys2)?;
        let actuals: Vec<String> = bytes
            .into_iter()
            .map(|b| String::from_utf8(b).unwrap())
            .collect();
        assert_eq!(actuals, vec![bil.to_string()]);

        assert!(ioduber.add(keys2, &bob)?);
        let bytes: Vec<Vec<u8>> = ioduber.get(keys2)?;
        let actuals: Vec<String> = bytes
            .into_iter()
            .map(|b| String::from_utf8(b).unwrap())
            .collect();
        assert_eq!(actuals, vec![bil.to_string(), bob.to_string()]);

        // Test trim of entire database
        assert!(ioduber.base.base.trim(&[] as &[&str], false)?); // default trims whole database
        assert!(ioduber.put(keys1, &[&bob, &bil])?);
        let bytes: Vec<Vec<u8>> = ioduber.get(keys1)?;
        let actuals: Vec<String> = bytes
            .into_iter()
            .map(|b| String::from_utf8(b).unwrap())
            .collect();
        assert_eq!(actuals, vec![bob.to_string(), bil.to_string()]);

        // Check database is auto-closed when test ends (similar to Python's context manager)
        // This happens automatically when lmdber goes out of scope

        Ok(())
    }
}
