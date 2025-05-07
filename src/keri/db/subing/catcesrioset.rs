use crate::cesr::Parsable;
use crate::keri::db::dbing::LMDBer;
use crate::keri::db::subing::catcesr::CatCesrSuberBase;
use crate::keri::db::subing::ioset::IoSetSuber;
use crate::keri::db::subing::SuberError;
use crate::Matter;
use std::sync::Arc;

pub struct CatCesrIoSetSuber<'db, M: Matter> {
    pub base: CatCesrSuberBase<'db, M>,
    pub io_set_suber: IoSetSuber<'db>,
}

impl<'db, M: Matter + Parsable> CatCesrIoSetSuber<'db, M> {
    pub fn new(
        db: Arc<&'db LMDBer>,
        subkey: &str,
        formats: Vec<String>,
        sep: Option<u8>,
        verify: bool,
    ) -> Result<Self, SuberError> {
        let base = CatCesrSuberBase::new(db.clone(), subkey, formats, sep, verify)?;
        let io_set_suber = IoSetSuber::new(db, subkey, sep, verify)?;

        Ok(Self { base, io_set_suber })
    }

    // Wrapper methods from CatCesrSuberBase (base)
    pub fn ser(&self, val: &[&dyn Matter]) -> Result<Vec<u8>, SuberError> {
        self.base.ser(val)
    }

    pub fn des(&self, val: &[u8]) -> Result<Vec<Box<dyn Matter>>, SuberError> {
        self.base.des(val)
    }

    // Wrapper methods from IoSetSuber (io_set_suber)
    pub fn put<K: AsRef<[u8]>>(
        &self,
        keys: &[K],
        vals: &[&dyn Matter],
    ) -> Result<bool, SuberError> {
        let sval = self.ser(vals)?;
        let sbuf = vec![&sval];
        self.io_set_suber.put(keys, &sbuf)
    }

    pub fn add<K: AsRef<[u8]>>(
        &self,
        keys: &[K],
        vals: &[&dyn Matter],
    ) -> Result<bool, SuberError> {
        let sval = self.ser(vals)?;
        self.io_set_suber.add(keys, &sval)
    }

    pub fn pin<K: AsRef<[u8]>>(
        &self,
        keys: &[K],
        valss: &[&[&dyn Matter]], // Now accepts an array of arrays of Matter
    ) -> Result<bool, SuberError> {
        let mut sbuf = Vec::with_capacity(valss.len());
        for vals in valss {
            sbuf.push(self.ser(vals)?);
        }
        self.io_set_suber
            .pin(keys, &sbuf.iter().collect::<Vec<_>>())
    }

    pub fn get<K: AsRef<[u8]>>(&self, keys: &[K]) -> Result<Vec<Vec<Box<dyn Matter>>>, SuberError> {
        let vals = self.io_set_suber.get::<K, Vec<u8>>(keys)?;
        let mut result = vec![];

        for val in vals {
            result.push(self.des(&val)?);
        }

        Ok(result)
    }

    pub fn get_iter<K: AsRef<[u8]>>(
        &self,
        keys: &[K],
    ) -> Result<Vec<Result<Vec<Box<dyn Matter>>, SuberError>>, SuberError> {
        // Get the Vec<u8> iterator from io_set_suber
        let iter = self.io_set_suber.get_iter::<K, Vec<u8>>(keys)?;

        // Collect and transform each result
        let mut results = Vec::new();
        for val_result in iter {
            let matter_result = match val_result {
                Ok(val) => self.des(&val),
                Err(e) => Err(e),
            };
            results.push(matter_result);
        }

        Ok(results)
    }

    pub fn get_last<K: AsRef<[u8]>>(
        &self,
        keys: &[K],
    ) -> Result<Option<Vec<Box<dyn Matter>>>, SuberError> {
        match self.io_set_suber.get_last::<K, Vec<u8>>(keys)? {
            Some(val) => {
                let deserialized = self.des(&val)?;
                Ok(Some(deserialized))
            }
            None => Ok(None),
        }
    }

    pub fn rem<K: AsRef<[u8]>>(
        &self,
        keys: &[K],
        vals: Option<&[&dyn Matter]>, // Changed to accept an array of Matter
    ) -> Result<bool, SuberError> {
        match vals {
            Some(vs) => {
                let sval = self.ser(vs)?; // Now we serialize all the values
                self.io_set_suber.rem(keys, Some(&sval))
            }
            None => self.io_set_suber.rem::<K, Vec<u8>>(keys, None),
        }
    }

    pub fn cnt<K: AsRef<[u8]>>(&self, keys: &[K]) -> Result<usize, SuberError> {
        self.io_set_suber.cnt(keys)
    }

    pub fn get_item_iter<K: AsRef<[u8]>>(
        &self,
        keys: &[K],
        topive: bool,
    ) -> Result<Vec<(Vec<Vec<u8>>, Vec<Box<dyn Matter>>)>, SuberError> {
        let items = self
            .io_set_suber
            .get_item_iter::<K, Vec<u8>>(keys, topive)?;
        self.process_items(items)
    }

    // Helper method for processing items (similar to CatCesrSuber)
    pub fn process_items(
        &self,
        items: Vec<(Vec<Vec<u8>>, Vec<u8>)>,
    ) -> Result<Vec<(Vec<Vec<u8>>, Vec<Box<dyn Matter>>)>, SuberError> {
        let mut result = Vec::with_capacity(items.len());

        for (key, val) in items {
            let deserialized = self.des(&val)?;
            result.push((key, deserialized));
        }

        Ok(result)
    }

    // Wrapper methods from SuberBase (base.base.base)
    pub fn to_key<K: AsRef<[u8]>>(&self, keys: &[K], topive: bool) -> Vec<u8> {
        self.base.base.base.to_key(keys, topive)
    }

    pub fn to_keys(&self, key: &[u8]) -> Vec<Vec<u8>> {
        self.base.base.base.to_keys(key)
    }

    pub fn trim<K: AsRef<[u8]>>(&self, keys: &[K], topive: bool) -> Result<bool, SuberError> {
        self.base.base.base.trim(keys, topive)
    }

    pub fn get_full_item_iter<K: AsRef<[u8]>>(
        &self,
        keys: &[K],
        topive: bool,
    ) -> Result<Vec<(Vec<Vec<u8>>, Vec<u8>)>, SuberError> {
        self.base.base.base.get_full_item_iter(keys, topive)
    }

    pub fn cnt_all(&self) -> Result<usize, SuberError> {
        self.base.base.base.cnt_all()
    }
}
#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::cesr::diger::Diger;
    use crate::cesr::indexing::siger::Siger;
    use crate::cesr::seqner::Seqner;
    use crate::keri::db::dbing::LMDBer;
    use crate::keri::db::subing::SuberError;
    use crate::Matter;

    use super::CatCesrIoSetSuber;

    #[test]
    fn test_cat_cesr_ioset_suber() -> Result<(), SuberError> {
        // Create temporary database with LMDBerBuilder
        let lmdb = LMDBer::builder().temp(true).build()?;
        let db = Arc::new(&lmdb);

        // Test default constructor
        let formats = vec!["seqner".to_string(), "diger".to_string()];
        let sdb =
            CatCesrIoSetSuber::<Diger>::new(db.clone(), "bags.", formats.clone(), None, false)?;

        // Create test data
        let sqr0 = Seqner::from_sn(20);
        assert_eq!(sqr0.qb64(), "0AAAAAAAAAAAAAAAAAAAAAAU");

        let dgr0 = Diger::from_ser(b"Hello Me Maties.", None)?;
        assert_eq!(dgr0.qb64(), "ELq6uSA62FaWKAQf2rclt4D1wRAeVwQ7hBucDG43GrsJ");

        let vals0: [&dyn Matter; 2] = [&sqr0, &dgr0];

        // Test serialization and deserialization
        let val0b = sdb.ser(&vals0)?;
        assert_eq!(val0b, [sqr0.qb64b(), dgr0.qb64b()].concat());

        let vals = sdb.des(&val0b)?;
        assert_eq!(vals.len(), 2);
        assert_eq!(vals[0].qb64(), sqr0.qb64());
        assert_eq!(vals[1].qb64(), dgr0.qb64());

        // Create more test data
        let sqr1 = Seqner::from_sn(32);
        assert_eq!(sqr1.qb64(), "0AAAAAAAAAAAAAAAAAAAAAAg");

        let dgr1 = Diger::from_ser(b"Hi Guy.", None)?;
        assert_eq!(dgr1.qb64(), "EAdfsnL-ko8ldxIZ9JL-KBTD4eMCqAAkEw4HmKFsT45C");

        let vals1: [&dyn Matter; 2] = [&sqr1, &dgr1];

        let sqr2 = Seqner::from_sn(1534);
        assert_eq!(sqr2.qb64(), "0AAAAAAAAAAAAAAAAAAAAAX-");

        let dgr2 = Diger::from_ser(b"Bye Bye Birdie.", None)?;
        assert_eq!(dgr2.qb64(), "EAO4UVcSfvfoGnSzJycMiihykJyYOshsyvU_l8U5TrO2");

        let vals2: [&dyn Matter; 2] = [&sqr2, &dgr2];

        let keys0 = ["a", "front"];
        let keys1 = ["ab", "side"];
        let keys2 = ["ac", "back"];

        // Test put and get
        assert!(sdb.put(&keys0, &vals0)?);
        assert_eq!(sdb.cnt(&keys0)?, 1);

        assert!(sdb.put(&keys0, &vals1)?);
        assert_eq!(sdb.cnt(&keys0)?, 2);

        let actuals = sdb.get(&keys0)?;
        assert_eq!(actuals.len(), 2);

        // Check first result matches vals0
        assert_eq!(actuals[0].len(), 2);
        assert_eq!(actuals[0][0].qb64(), sqr0.qb64());
        assert_eq!(actuals[0][1].qb64(), dgr0.qb64());

        // Check second result matches vals1
        assert_eq!(actuals[1].len(), 2);
        assert_eq!(actuals[1][0].qb64(), sqr1.qb64());
        assert_eq!(actuals[1][1].qb64(), dgr1.qb64());

        // Test get_last
        let actual = sdb.get_last(&keys0)?;
        assert!(actual.is_some());
        let actual = actual.unwrap();
        assert_eq!(actual.len(), 2);
        assert_eq!(actual[0].qb64(), sqr1.qb64());
        assert_eq!(actual[1].qb64(), dgr1.qb64());

        // Test remove
        assert!(sdb.rem(&keys0, None)?);
        let empty_results = sdb.get(&keys0)?;
        assert_eq!(empty_results.len(), 0);
        assert_eq!(sdb.cnt(&keys0)?, 0);

        // Test put again with different order
        assert!(sdb.put(&keys0, &vals1)?);
        assert!(sdb.put(&keys0, &vals0)?);

        let actuals = sdb.get(&keys0)?;
        assert_eq!(actuals.len(), 2);

        // Check first result matches vals1
        assert_eq!(actuals[0].len(), 2);
        assert_eq!(actuals[0][0].qb64(), sqr1.qb64());
        assert_eq!(actuals[0][1].qb64(), dgr1.qb64());

        // Check second result matches vals0
        assert_eq!(actuals[1].len(), 2);
        assert_eq!(actuals[1][0].qb64(), sqr0.qb64());
        assert_eq!(actuals[1][1].qb64(), dgr0.qb64());

        // Test get_last again
        let actual = sdb.get_last(&keys0)?;
        assert!(actual.is_some());
        let actual = actual.unwrap();
        assert_eq!(actual.len(), 2);
        assert_eq!(actual[0].qb64(), sqr0.qb64());
        assert_eq!(actual[1].qb64(), dgr0.qb64());
        // Create the values
        let sqr2 = Seqner::from_sn(1534);
        assert_eq!(sqr2.qb64(), "0AAAAAAAAAAAAAAAAAAAAAX-");

        let dgr2 = Diger::from_ser(b"Bye Bye Birdie.", None)?;
        assert_eq!(dgr2.qb64(), "EAO4UVcSfvfoGnSzJycMiihykJyYOshsyvU_l8U5TrO2");

        let vals2: [&dyn Matter; 2] = [&sqr2, &dgr2];

        // Test add
        assert!(sdb.add(&keys0, &vals2)?);

        assert_eq!(sdb.cnt(&keys0)?, 3);

        let actuals = sdb.get(&keys0)?;
        assert_eq!(actuals.len(), 3);

        // Check last result
        assert_eq!(actuals[2].len(), 2);
        assert_eq!(actuals[2][0].qb64(), sqr2.qb64());
        assert_eq!(actuals[2][1].qb64(), dgr2.qb64());

        // Test pin
        assert!(sdb.pin(&keys0, &[&vals0[..], &vals1[..]])?);
        assert_eq!(sdb.cnt(&keys0)?, 2);

        let actuals = sdb.get(&keys0)?;
        assert_eq!(actuals.len(), 2);

        // Check values after pin
        assert_eq!(actuals[0].len(), 2);
        assert_eq!(actuals[0][0].qb64(), sqr0.qb64());
        assert_eq!(actuals[0][1].qb64(), dgr0.qb64());

        assert_eq!(actuals[1].len(), 2);
        assert_eq!(actuals[1][0].qb64(), sqr1.qb64());
        assert_eq!(actuals[1][1].qb64(), dgr1.qb64());

        // Test put on another key
        assert!(sdb.put(&keys1, &vals2)?);
        assert!(sdb.put(&keys1, &vals1)?);
        assert_eq!(sdb.cnt(&keys1)?, 2);

        let actuals = sdb.get(&keys1)?;
        assert_eq!(actuals.len(), 2);

        // Check first result for keys1
        assert_eq!(actuals[0].len(), 2);
        assert_eq!(actuals[0][0].qb64(), sqr2.qb64());
        assert_eq!(actuals[0][1].qb64(), dgr2.qb64());

        // Test get_iter
        let vals_iter = sdb.get_iter(&keys1)?;
        let mut iter_results = Vec::new();

        for val_result in vals_iter {
            iter_results.push(val_result?);
        }

        assert_eq!(iter_results.len(), 2);
        assert_eq!(iter_results[0][0].qb64(), sqr2.qb64());
        assert_eq!(iter_results[0][1].qb64(), dgr2.qb64());
        assert_eq!(iter_results[1][0].qb64(), sqr1.qb64());
        assert_eq!(iter_results[1][1].qb64(), dgr1.qb64());

        // Test rem with specific value
        assert!(sdb.rem(&keys1, Some(&vals1[..]))?);
        assert_eq!(sdb.cnt(&keys1)?, 1);

        let actuals = sdb.get(&keys1)?;
        assert_eq!(actuals.len(), 1);
        assert_eq!(actuals[0][0].qb64(), sqr2.qb64());
        assert_eq!(actuals[0][1].qb64(), dgr2.qb64());

        // Test put on third key
        assert!(sdb.put(&keys2, &vals0)?);
        assert!(sdb.put(&keys2, &vals2)?);

        // Test get_item_iter without keys (all items)
        let items = sdb.get_item_iter(&[] as &[&str], false)?;

        // Convert to a comparable format
        let mut formatted_items = Vec::new();
        for (keys, vals) in items {
            let key_strs: Vec<String> = keys
                .iter()
                .map(|k| String::from_utf8_lossy(k).to_string())
                .collect();

            let val_qb64s: Vec<String> = vals.iter().map(|v| v.qb64()).collect();

            formatted_items.push((key_strs, val_qb64s));
        }

        // Test should have all items from all keys
        assert_eq!(formatted_items.len(), 5);

        // Verify that items contain all expected entries
        let expected_pairs = [
            (
                vec!["a".to_string(), "front".to_string()],
                vec![sqr0.qb64(), dgr0.qb64()],
            ),
            (
                vec!["a".to_string(), "front".to_string()],
                vec![sqr1.qb64(), dgr1.qb64()],
            ),
            (
                vec!["ab".to_string(), "side".to_string()],
                vec![sqr2.qb64(), dgr2.qb64()],
            ),
            (
                vec!["ac".to_string(), "back".to_string()],
                vec![sqr0.qb64(), dgr0.qb64()],
            ),
            (
                vec!["ac".to_string(), "back".to_string()],
                vec![sqr2.qb64(), dgr2.qb64()],
            ),
        ];

        // Verify all expected pairs are in formatted_items
        for expected in &expected_pairs {
            assert!(
                formatted_items
                    .iter()
                    .any(|item| { item.0 == expected.0 && item.1 == expected.1 }),
                "Expected item not found: {:?}",
                expected
            );
        }

        // Test getFullItemIter - accessing internal ordinal values
        let full_items = sdb.get_full_item_iter(&[] as &[&str], false)?;
        assert_eq!(full_items.len(), 5);

        // Process full items to extract the ordinal suffix
        let mut formatted_full_items = Vec::new();
        for (keys, val) in full_items {
            // Extract key parts including ordinal suffix
            let key_strs: Vec<String> = keys
                .iter()
                .map(|k| String::from_utf8_lossy(k).to_string())
                .collect();

            // Deserialize value
            let vals = sdb.des(&val)?;
            let val_qb64s: Vec<String> = vals.iter().map(|v| v.qb64()).collect();

            formatted_full_items.push((key_strs, val_qb64s));
        }

        // Verify that key format has three parts (key1, key2, ordinal)
        for (keys, _) in &formatted_full_items {
            assert_eq!(keys.len(), 3, "Full item keys should have 3 parts");
            assert!(
                keys[2].starts_with("00000000000000000000000000000"),
                "Third key part should be an ordinal: {}",
                keys[2]
            );
        }

        // Test get_item_iter with specific keys for keys0
        let items = sdb.get_item_iter(&keys0, false)?;

        let mut formatted_items = Vec::new();
        for (keys, vals) in items {
            let key_strs: Vec<String> = keys
                .iter()
                .map(|k| String::from_utf8_lossy(k).to_string())
                .collect();

            let val_qb64s: Vec<String> = vals.iter().map(|v| v.qb64()).collect();

            formatted_items.push((key_strs, val_qb64s));
        }

        assert_eq!(formatted_items.len(), 2);
        // Verify items for keys0
        assert!(formatted_items.iter().any(|item| {
            item.0 == vec!["a".to_string(), "front".to_string()]
                && item.1 == vec![sqr0.qb64(), dgr0.qb64()]
        }));
        assert!(formatted_items.iter().any(|item| {
            item.0 == vec!["a".to_string(), "front".to_string()]
                && item.1 == vec![sqr1.qb64(), dgr1.qb64()]
        }));

        // Test with topkeys for partial tree match
        let topkeys = ["a", ""];
        let items = sdb.get_item_iter(&topkeys, false)?;

        let mut formatted_items = Vec::new();
        for (keys, vals) in items {
            let key_strs: Vec<String> = keys
                .iter()
                .map(|k| String::from_utf8_lossy(k).to_string())
                .collect();

            let val_qb64s: Vec<String> = vals.iter().map(|v| v.qb64()).collect();

            formatted_items.push((key_strs, val_qb64s));
        }

        // Only keys0 entries should be returned with topkeys=["a", ""]
        assert_eq!(formatted_items.len(), 2);
        for item in &formatted_items {
            assert_eq!(item.0[0], "a");
            assert_eq!(item.0[1], "front");
        }

        // Test using get_full_item_iter with topkeys
        let items = sdb.get_full_item_iter(&topkeys, true)?;
        let mut vals_count = 0;

        // Process and convert the values to verify
        for (keys, val) in &items {
            let key_parts: Vec<String> = keys
                .iter()
                .map(|k| String::from_utf8_lossy(k).to_string())
                .collect();

            // Ensure we're looking at "a" prefix keys
            assert_eq!(key_parts[0], "a");

            // Count number of entries for verification
            vals_count += 1;
        }

        // Should get items with keys starting with "a"
        assert_eq!(vals_count, 2);

        // Test trim operation with specific prefix
        assert!(sdb.trim(&["ab", ""], false)?);

        // Verify keys1 entries are removed
        let items = sdb.get_item_iter(&keys1, false)?;
        assert_eq!(items.len(), 0);

        // Verify total count after trim
        let items = sdb.get_item_iter(&[] as &[&str], false)?;
        let mut formatted_items = Vec::new();
        for (keys, vals) in items {
            let key_strs: Vec<String> = keys
                .iter()
                .map(|k| String::from_utf8_lossy(k).to_string())
                .collect();

            let val_qb64s: Vec<String> = vals.iter().map(|v| v.qb64()).collect();

            formatted_items.push((key_strs, val_qb64s));
        }

        // Now should only have keys0 and keys2 entries (4 total)
        assert_eq!(formatted_items.len(), 4);

        // Check remaining keys
        let mut has_keys0 = false;
        let mut has_keys2 = false;
        for (keys, _) in &formatted_items {
            if keys[0] == "a" && keys[1] == "front" {
                has_keys0 = true;
            } else if keys[0] == "ac" && keys[1] == "back" {
                has_keys2 = true;
            }
        }
        assert!(has_keys0, "Keys0 entries should still exist after trim");
        assert!(has_keys2, "Keys2 entries should still exist after trim");

        // Test trim with top parameters (removing keys0 entries)
        assert!(sdb.trim(&["a"], true)?);

        // Verify keys0 entries are removed but keys2 still exist
        let items = sdb.get_item_iter(&[] as &[&str], false)?;
        let mut formatted_items = Vec::new();
        for (keys, vals) in items {
            let key_strs: Vec<String> = keys
                .iter()
                .map(|k| String::from_utf8_lossy(k).to_string())
                .collect();

            let val_qb64s: Vec<String> = vals.iter().map(|v| v.qb64()).collect();

            formatted_items.push((key_strs, val_qb64s));
        }

        // Should only have keys2 entries left
        assert_eq!(formatted_items.len(), 2);
        for (keys, _) in &formatted_items {
            assert_eq!(keys[0], "ac");
            assert_eq!(keys[1], "back");
        }

        // Add new test entries to verify partial tree trim
        assert!(sdb.put(&["b", "1"], &vals0)?);
        assert!(sdb.put(&["b", "2"], &vals1)?);
        assert!(sdb.put(&["bc", "3"], &vals2)?);
        assert!(sdb.put(&["ac", "4"], &vals0)?);

        // Verify all entries
        let items = sdb.get_item_iter(&[] as &[&str], false)?;
        assert_eq!(items.len(), 6);

        // Test trim with a different prefix
        assert!(sdb.trim(&["b", ""], false)?);

        // Verify "b" prefix entries are gone but "bc" remains
        let items = sdb.get_item_iter(&[] as &[&str], false)?;
        let mut formatted_items = Vec::new();
        for (keys, vals) in items {
            let key_strs: Vec<String> = keys
                .iter()
                .map(|k| String::from_utf8_lossy(k).to_string())
                .collect();

            let val_qb64s: Vec<String> = vals.iter().map(|v| v.qb64()).collect();

            formatted_items.push((key_strs, val_qb64s));
        }

        // Should have keys2 (2) + new keys ac/4 (1) + bc/3 (1) = 4 entries
        assert_eq!(formatted_items.len(), 4);

        // Check that "b" prefix entries are gone
        for (keys, _) in &formatted_items {
            assert!(keys[0] != "b", "Entries with 'b' prefix should be removed");
        }

        // Final verification - clear all entries
        assert!(sdb.trim(&[] as &[&str], false)?);
        let items = sdb.get_item_iter(&[] as &[&str], false)?;
        assert_eq!(items.len(), 0, "All entries should be removed");

        // First, create the test data (similar to Python test)
        let sqr0 = Seqner::from_sn(20);
        assert_eq!(sqr0.qb64(), "0AAAAAAAAAAAAAAAAAAAAAAU");

        let dgr0 = Diger::from_ser(b"Hello Me Maties.", None)?;
        assert_eq!(dgr0.qb64(), "ELq6uSA62FaWKAQf2rclt4D1wRAeVwQ7hBucDG43GrsJ");

        let vals0: [&dyn Matter; 2] = [&sqr0, &dgr0];

        let sqr1 = Seqner::from_sn(32);
        assert_eq!(sqr1.qb64(), "0AAAAAAAAAAAAAAAAAAAAAAg");

        let dgr1 = Diger::from_ser(b"Hi Guy.", None)?;
        assert_eq!(dgr1.qb64(), "EAdfsnL-ko8ldxIZ9JL-KBTD4eMCqAAkEw4HmKFsT45C");

        let vals1: [&dyn Matter; 2] = [&sqr1, &dgr1];

        let sqr2 = Seqner::from_sn(1534);
        assert_eq!(sqr2.qb64(), "0AAAAAAAAAAAAAAAAAAAAAX-");

        let dgr2 = Diger::from_ser(b"Bye Bye Birdie.", None)?;
        assert_eq!(dgr2.qb64(), "EAO4UVcSfvfoGnSzJycMiihykJyYOshsyvU_l8U5TrO2");

        let vals2: [&dyn Matter; 2] = [&sqr2, &dgr2];

        // Define the keys
        let keys0 = ["a", "front"];
        let keys1 = ["ab", "side"];
        let keys2 = ["ac", "back"];

        // Insert data into the database (as in the Python test)
        sdb.put(&keys0, &vals0)?;
        sdb.put(&keys0, &vals1)?;
        sdb.put(&keys1, &vals2)?;
        sdb.put(&keys2, &vals0)?;
        sdb.put(&keys2, &vals2)?;

        // Debug statement to verify data in database
        println!("DEBUG - Database state after insertion: keys0 count = {}, keys1 count = {}, keys2 count = {}",
                 sdb.cnt(&keys0)?, sdb.cnt(&keys1)?, sdb.cnt(&keys2)?);

        // Now call get_item_iter()
        let items = sdb.get_item_iter(&[] as &[&str], false)?;
        println!("DEBUG - get_item_iter returned {} items", items.len());

        // Convert to a comparable format
        let mut formatted_items = Vec::new();
        for (keys, vals) in items {
            let key_strs: Vec<String> = keys
                .iter()
                .map(|k| String::from_utf8_lossy(k).to_string())
                .collect();

            let val_qb64s: Vec<String> = vals.iter().map(|v| v.qb64()).collect();

            println!("DEBUG - Item: keys={:?}, vals={:?}", key_strs, val_qb64s);
            formatted_items.push((key_strs, val_qb64s));
        }

        // Now the test should pass with the expected 5 items
        assert_eq!(formatted_items.len(), 5);

        // Test get_item_iter with specific keys
        let items = sdb.get_item_iter(&keys1, false)?;

        let mut formatted_items = Vec::new();
        for (keys, vals) in items {
            let key_strs: Vec<String> = keys
                .iter()
                .map(|k| String::from_utf8_lossy(k).to_string())
                .collect();

            let val_qb64s: Vec<String> = vals.iter().map(|v| v.qb64()).collect();

            formatted_items.push((key_strs, val_qb64s));
        }

        assert_eq!(formatted_items.len(), 1);
        assert_eq!(
            formatted_items[0].0,
            vec!["ab".to_string(), "side".to_string()]
        );
        assert_eq!(formatted_items[0].1, vec![sqr2.qb64(), dgr2.qb64()]);

        // Test get_full_item_iter
        let items = sdb.get_full_item_iter(&["a", ""], true)?;

        // Should get items with keys starting with "a"
        assert!(items.len() >= 2); // At least the items with keys0
        let formats2 = vec!["siger".to_string()];
        // Test with Siger
        let sdb_siger =
            CatCesrIoSetSuber::<Siger>::new(db.clone(), "pigs.", formats2, None, false)?;

        let sig0_qb64 = "AACdI8OSQkMJ9r-xigjEByEjIua7LHH3AOJ22PQKqljMhuhcgh9nGRcKnsz5KvKd7K_H9-1298F4Id1DxvIoEmCQ";
        let val0 = Siger::from_qb64(sig0_qb64, None)?;

        let siger_keys = ["zeta", "cat"];
        assert!(sdb_siger.put(&siger_keys, &[&val0])?);

        let actuals = sdb_siger.get(&siger_keys)?;
        assert_eq!(actuals.len(), 1);
        assert_eq!(actuals[0].len(), 1);
        assert_eq!(actuals[0][0].qb64(), sig0_qb64);

        // Clean up - database will be closed when db goes out of scope
        Ok(())
    }
}
