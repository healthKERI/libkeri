use crate::keri::db::dbing::LMDBer;
use crate::keri::db::errors::DBError;
use crate::keri::db::subing::iodup::IoDupSuber;
use crate::keri::db::subing::OnSuberBase;
use crate::keri::db::subing::{SuberError, Utf8Codec, ValueCodec};
use std::sync::Arc;

use std::ops::Bound;

pub struct OnIoDupSuber<'db, C: ValueCodec = Utf8Codec> {
    pub on_base: OnSuberBase<'db, C>,
    pub io_dup_suber: IoDupSuber<'db, C>,
}

impl<'db, C: ValueCodec> OnIoDupSuber<'db, C> {
    pub fn new(
        db: Arc<&'db LMDBer>,
        subkey: &str,
        sep: Option<u8>,
        verify: bool,
    ) -> Result<Self, SuberError> {
        let on_base = OnSuberBase::new(db.clone(), subkey, sep, verify, Some(true))?;
        let io_dup_suber = IoDupSuber::new(db, subkey, sep, verify)?;

        Ok(Self {
            on_base,
            io_dup_suber,
        })
    }

    /// Adds val idempotently at key made from keys in insertion order using hidden ordinal proem.
    /// Idempotently means do not add val that is already in dup vals at key. Does not overwrite.
    pub fn add_on<K: AsRef<[u8]>, V: ?Sized + Clone + Into<Vec<u8>>>(
        &self,
        keys: &[K],
        on: u32,
        val: &V,
    ) -> Result<bool, SuberError> {
        let key = self.on_base._tokey(keys);
        let sval = self.on_base._ser(val)?;

        self.on_base
            .base
            .db
            .add_on_io_dup_val(
                &self.on_base.base.sdb,
                &key,
                Some(on as u64),
                &sval,
                Some([self.on_base.base.sep]),
            )
            .map_err(SuberError::DBError)
    }

    /// Appends a value and returns the ordinal number of the newly appended val
    pub fn append_on<K: AsRef<[u8]>, V: ?Sized + Clone + Into<Vec<u8>>>(
        &self,
        keys: &[K],
        val: &V,
    ) -> Result<u64, SuberError> {
        let key = self.on_base._tokey(keys);
        let sval = self.on_base._ser(val)?;

        self.on_base
            .base
            .db
            .append_on_io_dup_val(
                &self.on_base.base.sdb,
                &key,
                &sval,
                Some([self.on_base.base.sep]),
            )
            .map_err(SuberError::DBError)
    }

    /// Gets dup vals list at key made from keys
    pub fn get_on<K: AsRef<[u8]>, R: TryFrom<Vec<u8>>>(
        &self,
        keys: &[K],
        on: u32,
    ) -> Result<Vec<R>, SuberError>
    where
        <R as TryFrom<Vec<u8>>>::Error: std::fmt::Debug,
    {
        let key = self.on_base._tokey(keys);
        let mut results = Vec::new();

        self.on_base
            .base
            .db
            .get_on_io_dup_val_iter(
                &self.on_base.base.sdb,
                Some(&key),
                Some(on as u64),
                Some([self.on_base.base.sep]),
                |val| {
                    // Handle the deserialization manually, convert errors if needed
                    match self.on_base._des(&val) {
                        Ok(deserialized) => {
                            results.push(deserialized);
                            Ok(true) // Continue iteration
                        }
                        Err(e) => {
                            // Convert SuberError to DBError
                            Err(DBError::ValueError(format!(
                                "Deserialization error: {:?}",
                                e
                            )))
                        }
                    }
                },
            )
            .map_err(SuberError::DBError)?;

        Ok(results)
    }

    /// Removes entry at key made from keys and dup val that matches val if any,
    /// notwithstanding hidden ordinal proem. Otherwise deletes all dup values
    /// at key if any.
    pub fn rem_on<K: AsRef<[u8]>, V: ?Sized + Clone + Into<Vec<u8>>>(
        &self,
        keys: &[K],
        on: u32,
        val: Option<&V>,
    ) -> Result<bool, SuberError> {
        let key = self.on_base._tokey(keys);

        match val {
            Some(v) => {
                let sval = self.on_base._ser(v)?;
                self.on_base
                    .base
                    .db
                    .del_on_io_dup_val(
                        &self.on_base.base.sdb,
                        &key,
                        Some(on as u64),
                        &sval,
                        Some([self.on_base.base.sep]),
                    )
                    .map_err(SuberError::DBError)
            }
            None => self
                .on_base
                .base
                .db
                .del_on_io_dup_vals(
                    &self.on_base.base.sdb,
                    &key,
                    Some(on as u64),
                    Some([self.on_base.base.sep]),
                )
                .map_err(SuberError::DBError),
        }
    }

    /// Returns an iterator that yields deserialized values from the database
    pub fn get_on_iter<K: AsRef<[u8]>, R: TryFrom<Vec<u8>> + 'static>(
        &self,
        keys: &[K],
        on: u32,
    ) -> Result<Box<dyn Iterator<Item = Result<R, SuberError>> + '_>, SuberError>
    where
        <R as TryFrom<Vec<u8>>>::Error: std::fmt::Debug,
        SuberError: From<<R as TryFrom<Vec<u8>>>::Error>,
    {
        let key = self.on_base._tokey(keys);
        let sep = self.on_base.base.sep;

        // Create a collector that will hold deserialized values
        let mut collector = Vec::new();

        // Collect the values
        self.on_base
            .base
            .db
            .get_on_io_dup_val_iter(
                &self.on_base.base.sdb,
                Some(&key),
                Some(on as u64),
                Some([sep]),
                |val| {
                    collector.push(val);
                    Ok(true)
                },
            )
            .map_err(SuberError::DBError)?;

        // Create an iterator from the collected values
        let iter = collector.into_iter().map(move |val| {
            let deserialized: R = self.on_base._des(&val)?;
            Ok(deserialized)
        });

        Ok(Box::new(iter))
    }

    /// Returns an iterator that yields triples of (keys, on, val)
    pub fn get_on_item_iter<K: AsRef<[u8]>, R: TryFrom<Vec<u8>> + 'static>(
        &self,
        keys: &[K],
        on: u32,
    ) -> Result<Box<dyn Iterator<Item = Result<(Vec<Vec<u8>>, u64, R), SuberError>> + '_>, SuberError>
    where
        <R as TryFrom<Vec<u8>>>::Error: std::fmt::Debug,
        SuberError: From<<R as TryFrom<Vec<u8>>>::Error>,
    {
        let key = self.on_base._tokey(keys);
        let sep = self.on_base.base.sep;

        // Create a collector that will hold raw items
        let mut collector = Vec::new();

        // Collect the items
        self.on_base
            .base
            .db
            .get_on_io_dup_item_iter(
                &self.on_base.base.sdb,
                Some(&key),
                Some(on as u64),
                Some([sep]),
                |k, o, v| {
                    collector.push((k.to_vec(), o, v.to_vec()));
                    Ok(true)
                },
            )
            .map_err(SuberError::DBError)?;

        // Create an iterator from the collected items
        let iter = collector.into_iter().map(move |(k, o, v)| {
            let keys = self.on_base._tokeys(&k);
            let deserialized: R = self.on_base._des(&v)?;
            Ok((keys, o, deserialized))
        });

        Ok(Box::new(iter))
    }

    /// Returns an iterator that yields the last duplicate value for each key
    pub fn get_on_last_iter<K: AsRef<[u8]>, R: TryFrom<Vec<u8>> + 'static>(
        &self,
        keys: &[K],
        on: u32,
    ) -> Result<Box<dyn Iterator<Item = Result<R, SuberError>> + '_>, SuberError>
    where
        <R as TryFrom<Vec<u8>>>::Error: std::fmt::Debug,
        SuberError: From<<R as TryFrom<Vec<u8>>>::Error>,
    {
        let key = self.on_base._tokey(keys);
        let sep = self.on_base.base.sep;

        // Create a collector that will hold values
        let mut collector = Vec::new();

        // Collect the values
        self.on_base
            .base
            .db
            .get_on_io_dup_last_val_iter(
                &self.on_base.base.sdb,
                Some(&key),
                Some(on as u64),
                Some([sep]),
                |val| {
                    collector.push(val.to_vec());
                    Ok(true)
                },
            )
            .map_err(SuberError::DBError)?;

        // Create an iterator from the collected values
        let iter = collector
            .into_iter()
            .map(move |val| self.on_base._des(&val));

        Ok(Box::new(iter))
    }

    /// Returns an iterator that yields triples of (keys, on, val) for the last duplicate values
    pub fn get_on_last_item_iter<K: AsRef<[u8]>, R: TryFrom<Vec<u8>> + 'static>(
        &self,
        keys: &[K],
        on: u32,
    ) -> Result<Box<dyn Iterator<Item = Result<(Vec<Vec<u8>>, u64, R), SuberError>> + '_>, SuberError>
    where
        <R as TryFrom<Vec<u8>>>::Error: std::fmt::Debug,
        SuberError: From<<R as TryFrom<Vec<u8>>>::Error>,
    {
        let key = self.on_base._tokey(keys);
        let sep = self.on_base.base.sep;

        // Create a collector that will hold raw items
        let mut collector = Vec::new();

        // Collect the items
        self.on_base
            .base
            .db
            .get_on_io_dup_last_item_iter(
                &self.on_base.base.sdb,
                Some(&key),
                Some(on as u64),
                Some([sep]),
                |k, o, v| {
                    collector.push((k.to_vec(), o, v.to_vec()));
                    Ok(true)
                },
            )
            .map_err(SuberError::DBError)?;

        // Create an iterator from the collected items
        let iter = collector.into_iter().map(move |(k, o, v)| {
            let keys = self.on_base._tokeys(&k);
            let deserialized: R = self.on_base._des(&v)?;
            Ok((keys, o, deserialized))
        });

        Ok(Box::new(iter))
    }

    /// Returns an iterator that yields deserialized values from the database in reverse order
    pub fn get_on_back_iter<K: AsRef<[u8]>, R: TryFrom<Vec<u8>> + 'static>(
        &self,
        keys: &[K],
        on: u32,
    ) -> Result<Box<dyn Iterator<Item = Result<R, SuberError>> + '_>, SuberError>
    where
        <R as TryFrom<Vec<u8>>>::Error: std::fmt::Debug,
        SuberError: From<<R as TryFrom<Vec<u8>>>::Error>,
    {
        let key = self.on_base._tokey(keys);
        let sep = self.on_base.base.sep;

        // Create a collector that will hold values
        let mut collector = Vec::new();

        // Collect the values
        self.on_base
            .base
            .db
            .get_on_io_dup_val_back_iter(
                &self.on_base.base.sdb,
                Some(&key),
                Some(on as u64),
                Some([sep]),
                |val| {
                    collector.push(val.to_vec());
                    Ok(true)
                },
            )
            .map_err(SuberError::DBError)?;

        // Create an iterator from the collected values
        let iter = collector
            .into_iter()
            .map(move |val| self.on_base._des(&val));

        Ok(Box::new(iter))
    }

    /// Returns an iterator that yields triples of (keys, on, val) in reverse order
    pub fn get_on_item_back_iter<K: AsRef<[u8]>, R: TryFrom<Vec<u8>> + 'static>(
        &self,
        keys: &[K],
        on: u32,
    ) -> Result<Box<dyn Iterator<Item = Result<(Vec<Vec<u8>>, u64, R), SuberError>> + '_>, SuberError>
    where
        <R as TryFrom<Vec<u8>>>::Error: std::fmt::Debug,
        SuberError: From<<R as TryFrom<Vec<u8>>>::Error>,
    {
        let key = self.on_base._tokey(keys);
        let sep = self.on_base.base.sep;

        // Create a collector that will hold raw items
        let mut collector = Vec::new();

        // Collect the items
        self.on_base
            .base
            .db
            .get_on_io_dup_item_back_iter(
                &self.on_base.base.sdb,
                Some(&key),
                Some(on as u64),
                Some([sep]),
                |k, o, v| {
                    collector.push((k.to_vec(), o, v.to_vec()));
                    Ok(true)
                },
            )
            .map_err(SuberError::DBError)?;

        // Create an iterator from the collected items
        let iter = collector.into_iter().map(move |(k, o, v)| {
            let keys = self.on_base._tokeys(&k);
            let deserialized: R = self.on_base._des(&v)?;
            Ok((keys, o, deserialized))
        });

        Ok(Box::new(iter))
    }
}
#[cfg(test)]
mod tests {
    use crate::keri::db::dbing::keys::on_key;
    use crate::keri::db::dbing::{LMDBer, LMDBerBuilder};
    use crate::keri::db::subing::oniodup::OnIoDupSuber;
    use crate::keri::db::subing::{SuberError, Utf8Codec};
    use std::sync::Arc;
    use tempfile::tempdir;

    #[test]
    fn test_on_iodup_suber() -> Result<(), SuberError> {
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

        // Create OnIoDupSuber
        let db_ref = Arc::new(&db);
        let onsuber = OnIoDupSuber::<Utf8Codec>::new(db_ref, "bags.", None, false)?;
        assert!(onsuber.on_base.base.is_dupsort());

        let w = "Blue dog";
        let x = "Green tree";
        let y = "Red apple";
        let z = "White snow";

        // Test addOn, remOn
        assert!(onsuber.add_on(&["z"], 0, &w)?);
        let bytes: Vec<Vec<u8>> = onsuber.get_on(&["z"], 0)?;
        let vals: Vec<String> = bytes
            .iter()
            .map(|b| String::from_utf8(b.clone()).unwrap())
            .collect();
        assert_eq!(vals, vec![w.to_string()]);

        assert!(onsuber.add_on(&["z"], 0, &x)?);
        let bytes: Vec<Vec<u8>> = onsuber.get_on(&["z"], 0)?;
        let vals: Vec<String> = bytes
            .iter()
            .map(|b| String::from_utf8(b.clone()).unwrap())
            .collect();
        assert_eq!(vals, vec![w.to_string(), x.to_string()]);

        assert!(onsuber.add_on(&["z"], 1, &y)?);
        let bytes: Vec<Vec<u8>> = onsuber.get_on(&["z"], 1)?;
        let vals: Vec<String> = bytes
            .iter()
            .map(|b| String::from_utf8(b.clone()).unwrap())
            .collect();
        assert_eq!(vals, vec![y.to_string()]);

        assert!(onsuber.add_on(&["z"], 1, &z)?);
        let bytes: Vec<Vec<u8>> = onsuber.get_on(&["z"], 1)?;
        let vals: Vec<String> = bytes
            .iter()
            .map(|b| String::from_utf8(b.clone()).unwrap())
            .collect();
        assert_eq!(vals, vec![y.to_string(), z.to_string()]);

        assert_eq!(onsuber.on_base.cnt_on(&["z"], 0)?, 4);

        // Test getOnItemIter - collect items similar to Python test
        let mut items = Vec::new();
        let item_iter = onsuber.get_on_item_iter::<_, Vec<u8>>(&["z"], 0)?; // Use Vec<u8> here
        for item_result in item_iter {
            let (keys, on, val) = item_result?;
            let keys_vec = keys
                .iter()
                .map(|k| String::from_utf8(k.clone()).unwrap())
                .collect::<Vec<_>>();
            // Convert the Vec<u8> to String
            let val_string = String::from_utf8(val).unwrap();
            items.push((keys_vec, on, val_string));
        }
        assert_eq!(
            items,
            vec![
                (vec!["z".to_string()], 0, "Blue dog".to_string()),
                (vec!["z".to_string()], 0, "Green tree".to_string()),
                (vec!["z".to_string()], 1, "Red apple".to_string()),
                (vec!["z".to_string()], 1, "White snow".to_string())
            ]
        );

        // Test removal
        assert!(onsuber.rem_on(&["z"], 0, Some(&w))?);
        assert!(onsuber.rem_on(&["z"], 1, None::<&String>)?);

        // Check remaining items after removal
        let mut items = Vec::new();
        let item_iter = onsuber.get_on_item_iter::<_, Vec<u8>>(&["z"], 0)?;
        for item_result in item_iter {
            let (keys, on, val) = item_result?;
            let keys_vec = keys
                .iter()
                .map(|k| String::from_utf8(k.clone()).unwrap())
                .collect::<Vec<_>>();
            // Convert the Vec<u8> to String
            let val_string = String::from_utf8(val).unwrap();
            items.push((keys_vec, on, val_string));
        }
        assert_eq!(
            items,
            vec![(vec!["z".to_string()], 0, "Green tree".to_string())]
        );

        assert!(onsuber.rem_on(&["z"], 0, Some(&x))?);
        assert_eq!(onsuber.on_base.cnt_on(&["z"], 0)?, 0);

        // Test appendOn
        assert_eq!(onsuber.append_on(&["a"], &w)?, 0);
        assert_eq!(onsuber.append_on(&["a"], &x)?, 1);
        assert_eq!(onsuber.append_on(&["a"], &y)?, 2);
        assert_eq!(onsuber.append_on(&["a"], &z)?, 3);

        assert_eq!(onsuber.on_base.cnt_on(&["a"], 0)?, 4);
        assert_eq!(onsuber.on_base.cnt_on(&["a"], 2)?, 2);
        assert_eq!(onsuber.on_base.cnt_on(&["a"], 4)?, 0);

        // Test getItemIter
        let raw_items = onsuber.io_dup_suber.get_item_iter(
            &["a"] as &[&str],
            false, // Use a simple key prefix instead of on_key
        )?;

        let items_strings = raw_items
            .iter()
            .map(|(keys, val)| {
                let key_strings = keys
                    .iter()
                    .map(|k| String::from_utf8(k.clone()).unwrap())
                    .collect::<Vec<_>>();
                (key_strings, String::from_utf8(val.clone()).unwrap())
            })
            .collect::<Vec<_>>();

        // Check the structure of the items
        assert_eq!(items_strings.len(), 4);
        assert_eq!(items_strings[0].1, "Blue dog");
        assert_eq!(items_strings[1].1, "Green tree");
        assert_eq!(items_strings[2].1, "Red apple");
        assert_eq!(items_strings[3].1, "White snow");

        // Test getOnIter
        let mut vals = Vec::new();
        let val_iter = onsuber.get_on_iter::<_, Vec<u8>>(&["a"], 0)?;

        for val_result in val_iter {
            let raw_bytes = val_result?;
            let string_val = String::from_utf8(raw_bytes).expect("Invalid UTF-8 sequence");
            vals.push(string_val);
        }

        assert_eq!(
            vals,
            vec![
                "Blue dog".to_string(),
                "Green tree".to_string(),
                "Red apple".to_string(),
                "White snow".to_string()
            ]
        );

        // Test getOnIter with on=2
        let mut vals = Vec::new();
        let val_iter = onsuber.get_on_iter::<_, Vec<u8>>(&["a"], 2)?;
        for val_result in val_iter {
            let raw_bytes = val_result?;
            let string_val = String::from_utf8(raw_bytes).expect("Invalid UTF-8 sequence");
            vals.push(string_val);
        }
        assert_eq!(
            vals,
            vec!["Red apple".to_string(), "White snow".to_string()]
        );

        // Test getOnItemIter
        let mut items = Vec::new();
        let item_iter = onsuber.get_on_item_iter::<_, Vec<u8>>(&["a"], 0)?;

        for item_result in item_iter {
            let (keys, on, raw_bytes) = item_result?;
            let keys_vec = keys
                .iter()
                .map(|k| String::from_utf8(k.clone()).unwrap())
                .collect::<Vec<_>>();
            let val = String::from_utf8(raw_bytes).expect("Invalid UTF-8 sequence");
            items.push((keys_vec, on, val));
        }

        assert_eq!(
            items,
            vec![
                (vec!["a".to_string()], 0, "Blue dog".to_string()),
                (vec!["a".to_string()], 1, "Green tree".to_string()),
                (vec!["a".to_string()], 2, "Red apple".to_string()),
                (vec!["a".to_string()], 3, "White snow".to_string())
            ]
        );

        // Test getOnItemIter with on=2
        let mut items = Vec::new();
        let item_iter = onsuber.get_on_item_iter::<_, Vec<u8>>(&["a"], 2)?;
        for item_result in item_iter {
            let (keys, on, raw_bytes) = item_result?;
            let keys_vec = keys
                .iter()
                .map(|k| String::from_utf8(k.clone()).unwrap())
                .collect::<Vec<_>>();
            let val = String::from_utf8(raw_bytes).expect("Invalid UTF-8 sequence");
            items.push((keys_vec, on, val));
        }
        assert_eq!(
            items,
            vec![
                (vec!["a".to_string()], 2, "Red apple".to_string()),
                (vec!["a".to_string()], 3, "White snow".to_string())
            ]
        );

        // Test add with duplicates using direct add method
        assert!(onsuber
            .io_dup_suber
            .add(&[on_key("b".as_bytes(), 0, None)], &w)?);
        assert!(onsuber
            .io_dup_suber
            .add(&[on_key("b".as_bytes(), 1, None)], &x)?);
        assert!(onsuber
            .io_dup_suber
            .add(&[on_key("bc".as_bytes(), 0, None)], &y)?);
        assert!(onsuber
            .io_dup_suber
            .add(&[on_key("ac".as_bytes(), 0, None)], &z)?);

        assert_eq!(onsuber.on_base.cnt_on(&["b"], 0)?, 2);
        assert_eq!(onsuber.on_base.cnt_on(&["ac"], 2)?, 0);
        assert_eq!(onsuber.on_base.cnt_on(&[""], 0)?, 8);

        // Test getItemIter for all items
        let mut items = Vec::new();
        for item_result in onsuber
            .io_dup_suber
            .get_item_iter::<Vec<u8>>(&[] as &[Vec<u8>], false)?
        {
            // Manually convert Vec<u8> to String
            let (keys, raw_bytes) = item_result;
            let keys_vec = keys
                .iter()
                .map(|k| String::from_utf8(k.clone()).unwrap())
                .collect::<Vec<_>>();
            let val = String::from_utf8(raw_bytes).expect("Invalid UTF-8 sequence");
            items.push((keys_vec, val));
        }
        // Check we have correct number of items
        assert_eq!(items.len(), 8);

        // Test getOnItemIter for 'b'
        let mut items = Vec::new();
        let item_iter = onsuber.get_on_item_iter::<_, Vec<u8>>(&["b"], 0)?;
        for item_result in item_iter {
            let (keys, on, raw_bytes) = item_result?;
            let keys_vec = keys
                .iter()
                .map(|k| String::from_utf8(k.clone()).unwrap())
                .collect::<Vec<_>>();
            let val = String::from_utf8(raw_bytes).expect("Invalid UTF-8 sequence");
            items.push((keys_vec, on, val));
        }
        assert_eq!(
            items,
            vec![
                (vec!["b".to_string()], 0, "Blue dog".to_string()),
                (vec!["b".to_string()], 1, "Green tree".to_string())
            ]
        );

        // Test getOnIter for 'b'
        let mut vals = Vec::new();
        let val_iter = onsuber.get_on_iter::<_, Vec<u8>>(&["b"], 0)?;
        for val_result in val_iter {
            let raw_bytes = val_result?;
            let string_val = String::from_utf8(raw_bytes).expect("Invalid UTF-8 sequence");
            vals.push(string_val);
        }
        assert_eq!(vals, vec!["Blue dog".to_string(), "Green tree".to_string()]);

        // Test getOnIter with tuple key
        let mut vals = Vec::new();
        let val_iter = onsuber.get_on_iter::<_, Vec<u8>>(&["b"], 0)?;
        for val_result in val_iter {
            let raw_bytes = val_result?;
            let string_val = String::from_utf8(raw_bytes).expect("Invalid UTF-8 sequence");
            vals.push(string_val);
        }
        assert_eq!(vals, vec!["Blue dog".to_string(), "Green tree".to_string()]);

        // Test getOnItemIter with tuple key
        let mut items = Vec::new();
        let item_iter = onsuber.get_on_item_iter::<_, Vec<u8>>(&["b"], 0)?;
        for item_result in item_iter {
            let (keys, on, raw_bytes) = item_result?;
            let keys_vec = keys
                .iter()
                .map(|k| String::from_utf8(k.clone()).unwrap())
                .collect::<Vec<_>>();
            let val = String::from_utf8(raw_bytes).expect("Invalid UTF-8 sequence");
            items.push((keys_vec, on, val));
        }
        assert_eq!(
            items,
            vec![
                (vec!["b".to_string()], 0, "Blue dog".to_string()),
                (vec!["b".to_string()], 1, "Green tree".to_string())
            ]
        );

        // Test getOnItemIter with invalid key
        let mut items = Vec::new();
        let item_iter = onsuber.get_on_item_iter::<_, Vec<u8>>(&["b", ""], 0)?;
        for item_result in item_iter {
            let (keys, on, raw_bytes) = item_result?;
            let keys_vec = keys
                .iter()
                .map(|k| String::from_utf8(k.clone()).unwrap())
                .collect::<Vec<_>>();
            let val = String::from_utf8(raw_bytes).expect("Invalid UTF-8 sequence");
            items.push((keys_vec, on, val));
        }
        assert!(items.is_empty());

        // Test getOnIter with invalid key
        let mut vals = Vec::new();
        let val_iter = onsuber.get_on_iter::<_, Vec<u8>>(&["b", ""], 0)?;
        for val_result in val_iter {
            vals.push(val_result?);
        }
        assert!(vals.is_empty());

        // Test getOnItemIter with empty key (all items)
        let mut items = Vec::new();
        let item_iter = onsuber.get_on_item_iter::<_, Vec<u8>>(&[""], 0)?;
        for item_result in item_iter {
            let (keys, on, val) = item_result?;
            let keys_vec = keys
                .iter()
                .map(|k| String::from_utf8(k.clone()).unwrap())
                .collect::<Vec<_>>();
            items.push((keys_vec, on, val));
        }
        assert_eq!(items.len(), 8);

        // Test getOnIter with empty key (all items)
        let mut vals = Vec::new();
        let val_iter = onsuber.get_on_iter::<_, Vec<u8>>(&[""], 0)?;
        for val_result in val_iter {
            vals.push(val_result?);
        }
        assert_eq!(vals.len(), 8);

        // Test getOnItemIter with no key (all items)
        let mut items = Vec::new();
        let item_iter = onsuber.get_on_item_iter::<&str, Vec<u8>>(&[], 0)?;
        for item_result in item_iter {
            let (keys, on, val) = item_result?;
            let keys_vec = keys
                .iter()
                .map(|k| String::from_utf8(k.clone()).unwrap())
                .collect::<Vec<_>>();
            items.push((keys_vec, on, val));
        }
        assert_eq!(items.len(), 8);

        // Test getOnIter with no key (all items)
        let mut vals = Vec::new();
        let val_iter = onsuber.get_on_iter::<&str, Vec<u8>>(&[], 0)?;
        for val_result in val_iter {
            vals.push(val_result?);
        }
        assert_eq!(vals.len(), 8);

        // Test with duplicates
        assert!(onsuber
            .io_dup_suber
            .add(&[on_key("a".as_bytes(), 0, None)], &z)?);
        assert!(onsuber
            .io_dup_suber
            .add(&[on_key("a".as_bytes(), 1, None)], &y)?);
        assert!(onsuber
            .io_dup_suber
            .add(&[on_key("a".as_bytes(), 2, None)], &x)?);
        assert!(onsuber
            .io_dup_suber
            .add(&[on_key("a".as_bytes(), 3, None)], &w)?);

        assert_eq!(onsuber.on_base.cnt_on(&["a"], 0)?, 8);
        assert_eq!(onsuber.on_base.cnt_on(&["a"], 2)?, 4);
        assert_eq!(onsuber.on_base.cnt_on(&["a"], 4)?, 0);

        // Test getOnItemIter and getOnIter with duplicates
        let mut items = Vec::new();
        let item_iter = onsuber.get_on_item_iter::<_, Vec<u8>>(&["a"], 0)?;
        for item_result in item_iter {
            let (keys, on, val) = item_result?;
            let keys_vec = keys
                .iter()
                .map(|k| String::from_utf8(k.clone()).unwrap())
                .collect::<Vec<_>>();
            items.push((keys_vec, on, val));
        }
        assert_eq!(items.len(), 8);

        let mut vals = Vec::new();
        let val_iter = onsuber.get_on_iter::<_, Vec<u8>>(&["a"], 0)?;
        for val_result in val_iter {
            vals.push(val_result?);
        }
        assert_eq!(vals.len(), 8);

        // Test getOnItemBackIter and getOnBackIter
        let mut items = Vec::new();
        let item_iter = onsuber.get_on_item_back_iter::<_, Vec<u8>>(&["a"], 4)?;
        for item_result in item_iter {
            let (keys, on, val) = item_result?;
            let keys_vec = keys
                .iter()
                .map(|k| String::from_utf8(k.clone()).unwrap())
                .collect::<Vec<_>>();
            items.push((keys_vec, on, val));
        }
        assert_eq!(items.len(), 8);

        let mut vals = Vec::new();
        let val_iter = onsuber.get_on_back_iter::<_, Vec<u8>>(&["a"], 4)?;
        for val_result in val_iter {
            vals.push(val_result?);
        }
        assert_eq!(vals.len(), 8);

        // Test getOnItemIter and getOnIter with specific start point
        let mut items = Vec::new();
        let item_iter = onsuber.get_on_item_iter::<_, Vec<u8>>(&["a"], 2)?;
        for item_result in item_iter {
            let (keys, on, val) = item_result?;
            let keys_vec = keys
                .iter()
                .map(|k| String::from_utf8(k.clone()).unwrap())
                .collect::<Vec<_>>();
            items.push((keys_vec, on, val));
        }
        assert_eq!(items.len(), 4);

        let mut vals = Vec::new();
        let val_iter = onsuber.get_on_iter::<_, Vec<u8>>(&["a"], 2)?;
        for val_result in val_iter {
            vals.push(val_result?);
        }
        assert_eq!(vals.len(), 4);

        // Test getOnItemBackIter and getOnBackIter with specific start point
        let mut items = Vec::new();
        let item_iter = onsuber.get_on_item_back_iter::<_, Vec<u8>>(&["a"], 1)?;
        for item_result in item_iter {
            let (keys, on, val) = item_result?;
            let keys_vec = keys
                .iter()
                .map(|k| String::from_utf8(k.clone()).unwrap())
                .collect::<Vec<_>>();
            items.push((keys_vec, on, val));
        }
        assert_eq!(items.len(), 4);

        let mut vals = Vec::new();
        let val_iter = onsuber.get_on_back_iter::<_, Vec<u8>>(&["a"], 1)?;
        for val_result in val_iter {
            vals.push(val_result?);
        }
        assert_eq!(vals.len(), 4);

        // Test append with duplicates
        assert_eq!(onsuber.append_on(&["a"], &x)?, 4);
        assert_eq!(onsuber.on_base.cnt_on(&["a"], 0)?, 9);

        // Test removal
        assert!(onsuber.rem_on(&["a"], 1, None::<&String>)?);
        assert!(!onsuber.rem_on(&["a"], 1, None::<&String>)?);
        assert!(onsuber.rem_on(&["a"], 3, None::<&String>)?);
        assert!(!onsuber.rem_on(&["a"], 3, None::<&String>)?);

        assert_eq!(onsuber.on_base.cnt_on(&["a"], 0)?, 5);

        // Check remaining items
        let mut items = Vec::new();
        let item_iter = onsuber.get_on_item_iter::<_, Vec<u8>>(&["a"], 0)?;
        for item_result in item_iter {
            let (keys, on, val) = item_result?;
            let keys_vec = keys
                .iter()
                .map(|k| String::from_utf8(k.clone()).unwrap())
                .collect::<Vec<_>>();
            items.push((keys_vec, on, val));
        }
        assert_eq!(items.len(), 5);

        Ok(())
    }
}
