use crate::cesr::Matter;
use crate::cesr::Parsable;
use crate::keri::db::dbing::LMDBer;
use crate::keri::db::subing::cesr::CesrSuberBase;
use crate::keri::db::subing::ioset::IoSetSuber;
use crate::keri::db::subing::SuberError;
use std::sync::Arc;

pub struct CesrIoSetSuber<'db, M: Matter> {
    pub base: CesrSuberBase<'db, M>,
    pub io_set_suber: IoSetSuber<'db, crate::keri::db::subing::cesr::CesrCodec<M>>,
}

impl<'db, M: Matter + Parsable> CesrIoSetSuber<'db, M> {
    pub fn new(
        db: Arc<&'db LMDBer>,
        subkey: &str,
        sep: Option<u8>,
        verify: bool,
    ) -> Result<Self, SuberError> {
        let base = CesrSuberBase::new(db.clone(), subkey, sep, verify)?;
        let io_set_suber = IoSetSuber::new(db, subkey, sep, verify)?;

        Ok(Self { base, io_set_suber })
    }

    // Wrapper for CesrSuberBase methods
    pub fn _ser(&self, val: &M) -> Result<Vec<u8>, SuberError> {
        self.base.ser(val)
    }

    pub fn _des(&self, val: &[u8]) -> Result<M, SuberError> {
        self.base.des(val)
    }

    // Wrapper for IoSetSuber methods
    pub fn put<K: AsRef<[u8]>>(&self, keys: &[K], vals: &[&M]) -> Result<bool, SuberError> {
        // Convert CESR Matter objects to serialized form for IoSetSuber
        let ser_vals: Vec<Vec<u8>> = vals
            .iter()
            .map(|val| self._ser(val))
            .collect::<Result<Vec<Vec<u8>>, SuberError>>()?;

        let ser_vals_refs: Vec<&Vec<u8>> = ser_vals.iter().collect();

        self.io_set_suber.put(keys, &ser_vals_refs)
    }

    pub fn add<K: AsRef<[u8]>>(&self, keys: &[K], val: &M) -> Result<bool, SuberError> {
        let ser_val = self._ser(val)?;
        self.io_set_suber.add(keys, &ser_val)
    }

    pub fn pin<K: AsRef<[u8]>>(&self, keys: &[K], vals: &[&M]) -> Result<bool, SuberError> {
        // Convert CESR Matter objects to serialized form for IoSetSuber
        let ser_vals: Vec<Vec<u8>> = vals
            .iter()
            .map(|val| self._ser(val))
            .collect::<Result<Vec<Vec<u8>>, SuberError>>()?;

        let ser_vals_refs: Vec<&Vec<u8>> = ser_vals.iter().collect();

        self.io_set_suber.pin(keys, &ser_vals_refs)
    }

    pub fn get<K: AsRef<[u8]>>(&self, keys: &[K]) -> Result<Vec<M>, SuberError> {
        let ser_vals = self.io_set_suber.get::<K, Vec<u8>>(keys)?;
        let matters: Result<Vec<M>, SuberError> =
            ser_vals.into_iter().map(|val| self._des(&val)).collect();
        matters
    }

    pub fn get_iter<K: AsRef<[u8]>>(&self, keys: &[K]) -> Result<Vec<M>, SuberError> {
        let values = self.io_set_suber.get::<K, Vec<u8>>(keys)?;
        values.into_iter().map(|val| self._des(&val)).collect()
    }

    pub fn get_last<K: AsRef<[u8]>>(&self, keys: &[K]) -> Result<Option<M>, SuberError> {
        if let Some(ser_val) = self.io_set_suber.get_last::<K, Vec<u8>>(keys)? {
            Ok(Some(self._des(&ser_val)?))
        } else {
            Ok(None)
        }
    }

    pub fn rem<K: AsRef<[u8]>>(&self, keys: &[K], val: Option<&M>) -> Result<bool, SuberError> {
        match val {
            Some(m) => {
                let ser_val = self._ser(m)?;
                self.io_set_suber.rem::<K, Vec<u8>>(keys, Some(&ser_val))
            }
            None => self.io_set_suber.rem::<K, Vec<u8>>(keys, None),
        }
    }

    pub fn cnt<K: AsRef<[u8]>>(&self, keys: &[K]) -> Result<usize, SuberError> {
        self.io_set_suber.cnt(keys)
    }

    // Wrapper for get_item_iter with proper conversion to Matter objects
    pub fn get_item_iter<K: AsRef<[u8]>>(
        &self,
        keys: &[K],
        topive: bool,
    ) -> Result<Vec<(Vec<Vec<u8>>, M)>, SuberError> {
        let items = self.io_set_suber.get_full_item_iter(keys, topive)?;
        items
            .into_iter()
            .map(|(keys_vec, val)| Ok((keys_vec, self._des(&val)?)))
            .collect()
    }

    // Wrappers for SuberBase methods (accessed through io_set_suber.base)
    pub fn to_key<K: AsRef<[u8]>>(&self, keys: &[K], topive: bool) -> Vec<u8> {
        self.io_set_suber.base.to_key(keys, topive)
    }

    pub fn to_keys(&self, key: &[u8]) -> Vec<Vec<u8>> {
        self.io_set_suber.base.to_keys(key)
    }

    pub fn trim<K: AsRef<[u8]>>(&self, keys: &[K], topive: bool) -> Result<bool, SuberError> {
        self.io_set_suber.trim(keys, topive)
    }

    pub fn get_full_item_iter<K: AsRef<[u8]>>(
        &self,
        keys: &[K],
        topive: bool,
    ) -> Result<Vec<(Vec<Vec<u8>>, Vec<u8>)>, SuberError> {
        self.io_set_suber.get_full_item_iter(keys, topive)
    }

    pub fn cnt_all(&self) -> Result<usize, SuberError> {
        self.io_set_suber.base.cnt_all()
    }
    /// Returns whether this SuberBase is configured to support duplicate values for keys.
    ///
    /// # Returns
    /// * `bool` - True if duplicates are allowed
    pub fn is_dupsort(&self) -> bool {
        self.base.base.is_dupsort()
    }
}

#[cfg(test)]
mod tests {
    use crate::cesr::diger::Diger;
    use crate::cesr::saider::Saider;
    use crate::cesr::seqner::Seqner;
    use crate::cesr::Matter;
    use crate::keri::core::serdering::{sad::SadValue, Sadder};
    use crate::keri::db::dbing::{LMDBer, LMDBerBuilder};
    use crate::keri::db::subing::cesrioset::CesrIoSetSuber;
    use crate::keri::db::subing::SuberError;
    use indexmap::IndexMap;
    use serde_json::{json, Value};
    use std::sync::Arc;

    #[test]
    fn test_cesr_ioset_suber() -> Result<(), SuberError> {
        // Create a tempdir for test isolation (equivalent to with dbing.openLMDB() as db:)
        let db = LMDBerBuilder::default().name("test").temp(true).build()?;

        assert_eq!(db.name(), "test");
        assert!(db.opened());

        {
            // Create a CesrIoSetSuber instance
            let db_ref = Arc::new(&db);
            let cisuber = CesrIoSetSuber::<Saider>::new(db_ref, "bags.", None, false)?;
            assert!(!cisuber.is_dupsort());

            // Create sequence numbers
            let seqner0 = Seqner::from_sn(20);
            let seq0 = seqner0.qb64();
            assert_eq!(seq0, "0AAAAAAAAAAAAAAAAAAAAAAU");

            let seqner1 = Seqner::from_sn(10);
            let seq1 = seqner1.qb64();
            assert_eq!(seq1, "0AAAAAAAAAAAAAAAAAAAAAAK");

            // Create digest values
            let diger0 = Diger::from_ser("Hello Me Maties.".as_bytes(), None)?;
            let dig0 = diger0.qb64();
            assert_eq!(dig0, "ELq6uSA62FaWKAQf2rclt4D1wRAeVwQ7hBucDG43GrsJ");

            let diger1 = Diger::from_ser("Bye Y'all.".as_bytes(), None)?;
            let dig1 = diger1.qb64();
            assert_eq!(dig1, "EK--ZWfMjPZ8R90eDBuwy9umo1CnxpF95H550OGv65ry");

            // Create key tuples
            let keys0 = [seq0.as_str(), dig0.as_str()];
            let keys1 = [seq1.as_str(), dig1.as_str()];

            // Create the sad as a Sadder (IndexMap)
            let mut sad0: Sadder = IndexMap::new();
            sad0.insert("v".to_string(), SadValue::from_string("KERI10JSON000000_"));
            sad0.insert("t".to_string(), SadValue::from_string("rpy"));
            sad0.insert("d".to_string(), SadValue::from_string("")); // vacuous said
            sad0.insert(
                "dt".to_string(),
                SadValue::from_string("2020-08-22T17:50:12.988921+00:00"),
            );
            sad0.insert("r".to_string(), SadValue::from_string("/help/me"));

            // Create nested a dict
            let mut a_dict: IndexMap<String, SadValue> = IndexMap::new();
            a_dict.insert("name".to_string(), SadValue::from_string("John Jones"));
            a_dict.insert("role".to_string(), SadValue::from_string("Founder"));
            sad0.insert("a".to_string(), SadValue::Object(a_dict));

            // Saidify the sadder
            let (saider0, sadified0) = Saider::saidify(sad0, None, None, None, None)
                .map_err(|e| SuberError::ValueConversionError(e.to_string()))?;
            let said0 = saider0.qb64().to_string();
            assert_eq!(said0, "EKwVGsUU1sUlYRq_g2Z3_3GOIREYtlQ3kPSNjpg8w4j0");

            // Create second sad
            let mut sad1: Sadder = IndexMap::new();
            sad1.insert("v".to_string(), SadValue::from_string("KERI10JSON000000_"));
            sad1.insert("t".to_string(), SadValue::from_string("rpy"));
            sad1.insert("d".to_string(), SadValue::from_string("")); // vacuous said
            sad1.insert(
                "dt".to_string(),
                SadValue::from_string("2020-08-22T17:50:12.988921+00:00"),
            );
            sad1.insert("r".to_string(), SadValue::from_string("/help/you"));

            // Create nested a dict
            let mut a_dict: IndexMap<String, SadValue> = IndexMap::new();
            a_dict.insert("name".to_string(), SadValue::from_string("Sue Swan"));
            a_dict.insert("role".to_string(), SadValue::from_string("Creator"));
            sad1.insert("a".to_string(), SadValue::Object(a_dict));

            let (saider1, sadified1) = Saider::saidify(sad1, None, None, None, None)
                .map_err(|e| SuberError::ValueConversionError(e.to_string()))?;
            let said1 = saider1.qb64().to_string();
            assert_eq!(said1, "EPl1dMAs2RDsZ12K3yxA0fTHP6dRJzDkStf65VVeFxne");

            // Create third sad
            let mut sad2: Sadder = IndexMap::new();
            sad2.insert("v".to_string(), SadValue::from_string("KERI10JSON000000_"));
            sad2.insert("t".to_string(), SadValue::from_string("rpy"));
            sad2.insert("d".to_string(), SadValue::from_string("")); // vacuous said
            sad2.insert(
                "dt".to_string(),
                SadValue::from_string("2020-08-22T17:50:30.988921+00:00"),
            );
            sad2.insert("r".to_string(), SadValue::from_string("/find/out"));

            // Create nested a dict
            let mut a_dict: IndexMap<String, SadValue> = IndexMap::new();
            a_dict.insert("name".to_string(), SadValue::from_string("Zoe Zigler"));
            a_dict.insert("role".to_string(), SadValue::from_string("Maven"));
            sad2.insert("a".to_string(), SadValue::Object(a_dict));

            let (saider2, sadified2) = Saider::saidify(sad2, None, None, None, None)
                .map_err(|e| SuberError::ValueConversionError(e.to_string()))?;
            let said2 = saider2.qb64().to_string();
            assert_eq!(said2, "EJxOaEsBSObrcmrsnlfHOdVAowGhUBKoE2Ce3TZ4Mhgu");

            // Test put and get
            assert!(cisuber.put(&keys0, &[&saider1, &saider0])?);
            assert_eq!(cisuber.cnt(&keys0)?, 2);

            let actuals = cisuber.get(&keys0)?;
            assert_eq!(actuals.len(), 2);
            let sers: Vec<String> = actuals.iter().map(|actual| actual.qb64()).collect();
            assert_eq!(sers, vec![said1.clone(), said0.clone()]);

            if let Some(actual) = cisuber.get_last(&keys0)? {
                assert_eq!(actual.qb64(), said0);
            } else {
                panic!("Expected a value from get_last but got None");
            }

            // Test rem
            assert!(cisuber.rem(&keys0, None)?);
            let actuals = cisuber.get(&keys0)?;
            assert!(actuals.is_empty());
            assert_eq!(cisuber.cnt(&keys0)?, 0);

            // Test put again with different order
            assert!(cisuber.put(&keys0, &[&saider0, &saider1])?);
            assert_eq!(cisuber.cnt(&keys0)?, 2);

            let actuals = cisuber.get(&keys0)?;
            assert_eq!(actuals.len(), 2);
            let sers: Vec<String> = actuals.iter().map(|actual| actual.qb64()).collect();
            assert_eq!(sers, vec![said0.clone(), said1.clone()]);

            if let Some(actual) = cisuber.get_last(&keys0)? {
                assert_eq!(actual.qb64(), said1);
            } else {
                panic!("Expected a value from get_last but got None");
            }

            // Test add
            assert!(cisuber.add(&keys0, &saider2)?);
            assert_eq!(cisuber.cnt(&keys0)?, 3);

            let actuals = cisuber.get(&keys0)?;
            assert_eq!(actuals.len(), 3);
            let sers: Vec<String> = actuals.iter().map(|actual| actual.qb64()).collect();
            assert_eq!(sers, vec![said0.clone(), said1.clone(), said2.clone()]);

            if let Some(actual) = cisuber.get_last(&keys0)? {
                assert_eq!(actual.qb64(), said2);
            } else {
                panic!("Expected a value from get_last but got None");
            }

            // Test pin (replaces all values)
            assert!(cisuber.pin(&keys0, &[&saider1, &saider2])?);
            assert_eq!(cisuber.cnt(&keys0)?, 2);

            let actuals = cisuber.get(&keys0)?;
            assert_eq!(actuals.len(), 2);
            let sers: Vec<String> = actuals.iter().map(|actual| actual.qb64()).collect();
            assert_eq!(sers, vec![said1.clone(), said2.clone()]);

            // Test with another key
            assert!(cisuber.put(&keys1, &[&saider2, &saider1, &saider0])?);
            assert_eq!(cisuber.cnt(&keys1)?, 3);

            let actuals = cisuber.get(&keys1)?;
            assert_eq!(actuals.len(), 3);
            let sers: Vec<String> = actuals.iter().map(|actual| actual.qb64()).collect();
            assert_eq!(sers, vec![said2.clone(), said1.clone(), said0.clone()]);

            // Test rem with specific value
            assert!(cisuber.rem(&keys1, Some(&saider1))?);
            assert_eq!(cisuber.cnt(&keys1)?, 2);

            let actuals = cisuber.get(&keys1)?;
            assert_eq!(actuals.len(), 2);
            let sers: Vec<String> = actuals.iter().map(|actual| actual.qb64()).collect();
            assert_eq!(sers, vec![said2.clone(), said0.clone()]);

            // Test get_iter
            let actuals = cisuber.get_iter(&keys1)?;
            let sers: Vec<String> = actuals.iter().map(|actual| actual.qb64()).collect();
            assert_eq!(sers, vec![said2.clone(), said0.clone()]);

            // Test get_item_iter for all items
            let items = cisuber.get_item_iter(&[] as &[&str], false)?;

            // Check total number of items matches expected
            assert_eq!(items.len(), 4);

            // Convert items to human-readable format for assertions
            let items_converted: Vec<(Vec<String>, String)> = items
                .into_iter()
                .map(|(keys, val)| {
                    (
                        keys.into_iter()
                            .map(|key| String::from_utf8(key).unwrap())
                            .collect(),
                        val.qb64(),
                    )
                })
                .collect();

            // Test get_full_item_iter for all items
            let full_items = cisuber.get_full_item_iter(&[] as &[&str], false)?;
            assert_eq!(full_items.len(), 4);

            // Convert keys to string for easier assertions
            let full_items_converted: Vec<(Vec<String>, Vec<u8>)> = full_items
                .into_iter()
                .map(|(keys, val)| {
                    (
                        keys.into_iter()
                            .map(|key| String::from_utf8(key).unwrap())
                            .collect(),
                        val,
                    )
                })
                .collect();

            // Each key should have 3 parts (2 parts + ordinal)
            for (keys, _) in &full_items_converted {
                assert_eq!(keys.len(), 3, "Full item key should have 3 parts");
                // Third part should be the ordinal
                assert!(
                    keys[2].starts_with("000000000000000000000000000000"),
                    "Third part of key should be ordinal: {}",
                    keys[2]
                );
            }

            // Test get_item_iter with specific keys
            let items = cisuber.get_item_iter(&keys0, false)?;
            let items_converted: Vec<(Vec<String>, String)> = items
                .into_iter()
                .map(|(keys, val)| {
                    (
                        keys.into_iter()
                            .map(|key| String::from_utf8(key).unwrap())
                            .collect(),
                        val.qb64(),
                    )
                })
                .collect();

            assert_eq!(items_converted.len(), 2);
            assert_eq!(items_converted[0].0[0], seq0);
            assert_eq!(items_converted[0].0[1], dig0);

            // Test with top keys (prefix match)
            let topkeys = [seq1, String::from("")];
            let items = cisuber.get_item_iter(&topkeys, false)?;
            let items_converted: Vec<(Vec<String>, String)> = items
                .into_iter()
                .map(|(keys, val)| {
                    (
                        keys.into_iter()
                            .map(|key| String::from_utf8(key).unwrap())
                            .collect(),
                        val.qb64(),
                    )
                })
                .collect();

            assert_eq!(items_converted.len(), 2);

            // Test get_full_item_iter with specific prefix
            let topkeys = [seq0, String::from("")];
            let items = cisuber.get_full_item_iter(&topkeys, false)?;
            let items_converted: Vec<(Vec<String>, Vec<u8>)> = items
                .into_iter()
                .map(|(keys, val)| {
                    (
                        keys.into_iter()
                            .map(|key| String::from_utf8(key).unwrap())
                            .collect(),
                        val,
                    )
                })
                .collect();

            assert_eq!(items_converted.len(), 2);
        }

        Ok(())
    }
}
