use crate::cesr::dater::Dater;
use crate::cesr::diger::Diger;
use crate::cesr::indexing::siger::Siger;
use crate::cesr::seqner::Seqner;
use crate::cesr::{BaseMatter, Parsable};
use crate::keri::db::dbing::LMDBer;
use crate::keri::db::subing::cesr::CesrSuberBase;
use crate::keri::db::subing::{Suber, SuberError};
use crate::Matter;
use std::any::Any;
use std::sync::Arc;

pub struct CatCesrSuberBase<'db, M: Matter> {
    pub base: CesrSuberBase<'db, M>,
    pub formats: Vec<String>,
}

impl<'db, M: Matter + Parsable> CatCesrSuberBase<'db, M> {
    /// Creates a new CatCesrSuberBase
    ///
    /// Parameters:
    ///   - db: The base LMDB database
    ///   - subkey: The key for the sub-database
    ///   - formats: Array of format strings that determine which serialization/deserialization methods to use
    ///   - sep: Optional separator for keys
    ///   - verify: Whether to verify data when deserializing
    pub fn new(
        db: Arc<&'db LMDBer>,
        subkey: &str,
        formats: Vec<String>,
        sep: Option<u8>,
        verify: bool,
    ) -> Result<Self, SuberError> {
        let base = CesrSuberBase::new(db, subkey, sep, verify)?;

        Ok(Self { base, formats })
    }

    /// Generic serialization dispatch method that handles any Matter type
    /// but with specific logic for the supported format types
    pub fn ser(&self, val: &[&dyn Matter]) -> Result<Vec<u8>, SuberError> {
        match self.formats.as_slice() {
            // Handle dater, seqner, diger format
            [a, b, c] if a == "dater" && b == "seqner" && c == "diger" => {
                // Validate we have exactly 3 values
                if val.len() != 3 {
                    return Err(SuberError::ValueConversionError(
                        "Expected 3 values for dater, seqner, diger format".to_string(),
                    ));
                }

                self.ser_from_dater_seqner_diger(val[0], val[1], val[2])
            }

            // Handle siger format
            [a] if a == "siger" => {
                // Validate we have exactly 1 value
                if val.len() != 1 {
                    return Err(SuberError::ValueConversionError(
                        "Expected 1 value for siger format".to_string(),
                    ));
                }

                let siger = match val[0].as_any().downcast_ref::<Siger>() {
                    Some(s) => s,
                    None => {
                        return Err(SuberError::ValueConversionError(
                            "Value must be a Siger".to_string(),
                        ))
                    }
                };

                self.ser_from_siger(siger)
            }

            // Default case - handle any Matter object
            _ => {
                // Serialize directly using qb64b
                Ok(val[0].qb64b())
            }
        }
    }

    /// Generic deserialization dispatch method that handles any Matter type
    /// but with specific logic for the supported format types
    pub fn des(&self, val: &[u8]) -> Result<Vec<Box<dyn Matter>>, SuberError> {
        match self.formats.as_slice() {
            // Handle dater, seqner, diger format
            [a, b, c] if a == "dater" && b == "seqner" && c == "diger" => {
                self.des_to_dater_seqner_diger(val)
            }

            // Handle siger format
            [a] if a == "siger" => self.des_to_siger(val),

            // Default case - handle any Matter using BaseMatter
            _ => {
                // For generic format, deserialize as BaseMatter
                let matter = BaseMatter::from_qb64b(&mut val.to_vec(), None)
                    .map_err(|e| SuberError::MatterError(e))?;

                // Return as a boxed Matter trait object
                let boxed: Box<dyn Matter> = Box::new(matter);
                Ok(vec![boxed])
            }
        }
    }

    /// Serializes from a Siger to bytes
    pub fn ser_from_siger(&self, siger: &Siger) -> Result<Vec<u8>, SuberError> {
        Ok(siger.qb64b())
    }

    /// Deserializes from bytes to a Siger
    pub fn des_to_siger(&self, val: &[u8]) -> Result<Vec<Box<dyn Matter>>, SuberError> {
        // Convert val to a mutable vector so we can use from_qb64b
        let mut data = val.to_vec();

        // Parse the Siger
        let siger = Siger::from_qb64b(&mut data, Some(true)).map_err(|e| {
            SuberError::DeserializationError(format!("Failed to parse Siger: {}", e))
        })?;

        // Return as a vector of boxed Matter traits
        let result: Vec<Box<dyn Matter>> = vec![Box::new(siger)];

        Ok(result)
    }

    /// Serializes from a tuple of (Dater, Seqner, Diger) to bytes
    pub fn ser_from_dater_seqner_diger(
        &self,
        dater: &dyn Matter,
        seqner: &dyn Matter,
        diger: &dyn Matter,
    ) -> Result<Vec<u8>, SuberError> {
        // Concatenate the qb64b of each instance
        let mut result = Vec::new();
        result.extend_from_slice(&dater.qb64b());
        result.extend_from_slice(&seqner.qb64b());
        result.extend_from_slice(&diger.qb64b());

        Ok(result)
    }

    /// Deserializes from bytes to a tuple of (Dater, Seqner, Diger)
    pub fn des_to_dater_seqner_diger(
        &self,
        val: &[u8],
    ) -> Result<Vec<Box<dyn Matter>>, SuberError> {
        // Convert val to a mutable vector so we can use from_qb64b
        let mut data = val.to_vec();

        // Parse the Dater
        let dater = Dater::from_qb64b(&mut data, Some(true)).map_err(|e| {
            SuberError::DeserializationError(format!("Failed to parse Dater: {}", e))
        })?;

        // Parse the Seqner
        let seqner = Seqner::from_qb64b(&mut data, Some(true)).map_err(|e| {
            SuberError::DeserializationError(format!("Failed to parse Seqner: {}", e))
        })?;

        // Parse the Diger
        let diger = Diger::from_qb64b(&mut data, Some(true)).map_err(|e| {
            SuberError::DeserializationError(format!("Failed to parse Diger: {}", e))
        })?;

        let result: Vec<Box<dyn Matter>> = vec![Box::new(dater), Box::new(seqner), Box::new(diger)];

        Ok(result)
    }
}

/// CatCesrSuber is a wrapper around CatCesrSuberBase that provides the complete Suber interface

pub struct CatCesrSuber<'db, M: Matter> {
    pub base: CatCesrSuberBase<'db, M>,
    pub suber: Suber<'db>,
}

impl<'db, M: Matter + Parsable> CatCesrSuber<'db, M> {
    /// Creates a new CatCesrSuber
    ///
    /// Parameters:
    ///   - db: The base LMDB database
    ///   - subkey: The key for the sub-database
    ///   - formats: Array of format strings that determine which serialization/deserialization methods to use
    ///   - sep: Optional separator for keys
    ///   - verify: Whether to verify data when deserializing
    pub fn new(
        db: Arc<&'db LMDBer>,
        subkey: &str,
        formats: Vec<String>,
        sep: Option<u8>,
        verify: bool,
    ) -> Result<Self, SuberError> {
        let base = CatCesrSuberBase::new(db.clone(), subkey, formats, sep, verify)?;
        let suber = Suber::new(db, subkey, sep, verify)?;

        Ok(Self { base, suber })
    }

    // Delegate to the suber.put method
    pub fn put<K: AsRef<[u8]>>(
        &self,
        keys: &[K],
        vals: &[&dyn Matter],
    ) -> Result<bool, SuberError> {
        // Serialize Matter values to Vec<u8> using base.ser
        let val_bytes = self.base.ser(vals)?;
        // Then delegate to suber.put
        self.suber.put(keys, &val_bytes)
    }

    // Delegate to the suber.pin method
    pub fn pin<K: AsRef<[u8]>>(
        &self,
        keys: &[K],
        vals: &[&dyn Matter],
    ) -> Result<bool, SuberError> {
        // Serialize Matter values to Vec<u8> using base.ser
        let val_bytes = self.base.ser(vals)?;
        // Then delegate to suber.pin
        self.suber.pin(keys, &val_bytes)
    }

    // Delegate to the suber.get method
    pub fn get<K: AsRef<[u8]>>(
        &self,
        keys: &[K],
    ) -> Result<Option<Vec<Box<dyn Matter>>>, SuberError> {
        // Get the value as Vec<u8> from suber
        let val_opt = self.suber.get::<K, Vec<u8>>(keys)?;

        // If value exists, deserialize it to Vec<Box<dyn Matter>>
        match val_opt {
            Some(val_bytes) => {
                let deserialized = self.base.des(&val_bytes)?;
                Ok(Some(deserialized))
            }
            None => Ok(None),
        }
    }

    /// Removes a value from the database
    pub fn rem<K: AsRef<[u8]>>(&self, keys: &[K]) -> Result<bool, SuberError> {
        self.suber.rem(keys)
    }

    /// Trims keys in the database
    pub fn trim<K: AsRef<[u8]>>(&self, keys: &[K], topive: bool) -> Result<bool, SuberError> {
        self.suber.trim(keys, topive)
    }

    /// Gets all items for a set of keys
    pub fn get_full_item_iter<K: AsRef<[u8]>>(
        &self,
        keys: &[K],
        topive: bool,
    ) -> Result<Vec<(Vec<Vec<u8>>, Vec<u8>)>, SuberError> {
        self.suber.base.get_full_item_iter(keys, topive)
    }

    /// Gets filtered items for a set of keys
    pub fn get_item_iter<K: AsRef<[u8]>>(
        &self,
        keys: &[K],
        topive: bool,
    ) -> Result<Vec<(Vec<Vec<u8>>, Vec<u8>)>, SuberError> {
        self.suber.base.get_item_iter(keys, topive)
    }

    /// Process raw items into deserialized values
    pub fn process_items(
        &self,
        items: Vec<(Vec<Vec<u8>>, Vec<u8>)>,
    ) -> Result<Vec<(Vec<Vec<u8>>, Vec<Box<dyn Matter>>)>, SuberError> {
        let mut result = Vec::new();

        for (keys, val) in items {
            let deserialized = self.base.des(&val)?;
            result.push((keys, deserialized));
        }

        Ok(result)
    }
    /// Delegate to the suber.base.to_key method
    pub fn to_key<K: AsRef<[u8]>>(&self, keys: &[K], topive: bool) -> Vec<u8> {
        self.suber.base.to_key(keys, topive)
    }

    /// Delegate to the suber.base.to_keys method
    pub fn to_keys(&self, key: &[u8]) -> Vec<Vec<u8>> {
        self.suber.base.to_keys(key)
    }

    /// Counts all items in the database
    pub fn cnt_all(&self) -> Result<usize, SuberError> {
        self.suber.cnt_all()
    }
}

#[cfg(test)]
mod tests {
    use crate::cesr::dater::Dater;
    use crate::cesr::diger::Diger;
    use crate::cesr::indexing::siger::Siger;
    use crate::cesr::seqner::Seqner;
    use crate::cesr::{BaseMatter, Matter, Parsable};
    use crate::keri::db::dbing::LMDBerBuilder;
    use crate::keri::db::subing::catcesr::CatCesrSuber;
    use crate::keri::db::subing::SuberError;
    use std::sync::Arc;

    #[test]
    fn test_cat_cesr_suber() -> Result<(), SuberError> {
        // Open a test database
        let db = LMDBerBuilder::default()
            .name("test")
            .temp(true)
            .build()
            .unwrap();

        assert_eq!(db.name(), "test");
        assert!(db.opened());

        {
            // Test Single Matter type
            let db_ref = Arc::new(&db);
            let sdb = CatCesrSuber::<BaseMatter>::new(
                db_ref.clone(),
                "bags.",
                vec![], // empty formats defaults to BaseMatter
                Some(b'.'),
                false,
            )?;

            // Test data with BaseMatter
            let matb0 = "BDzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc";
            let matter0 = BaseMatter::from_qb64(matb0).unwrap();
            let vals0: Vec<&dyn Matter> = vec![&matter0];

            let matb1 = "BHHzqZWzwE-Wk7K0gzQPYGGwTmuupUhPx5_y1x4ejhcc";
            let matter1 = BaseMatter::from_qb64(matb1).unwrap();
            let vals1: Vec<&dyn Matter> = vec![&matter1];

            // Test with tuple keys
            let keys0 = ["alpha", "dog"];

            // Test put and get
            assert!(sdb.put(&keys0, &vals0)?);
            let actuals = sdb.get(&keys0)?;
            assert!(actuals.is_some());

            let actuals = actuals.unwrap();
            assert_eq!(actuals.len(), 1);

            // Downcast the retrieved Matter
            let retrieved = actuals[0].as_any().downcast_ref::<BaseMatter>().unwrap();
            assert_eq!(retrieved.qb64(), matter0.qb64());

            // Test remove
            assert!(sdb.rem(&keys0)?);
            let actuals = sdb.get(&keys0)?;
            assert!(actuals.is_none());

            // Put again
            assert!(sdb.put(&keys0, &vals0)?);
            let actuals = sdb.get(&keys0)?.unwrap();
            assert_eq!(actuals.len(), 1);
            let retrieved = actuals[0].as_any().downcast_ref::<BaseMatter>().unwrap();
            assert_eq!(retrieved.qb64(), matter0.qb64());

            // Try regular put with same key (should fail as dupsort is false)
            let result = sdb.put(&keys0, &vals1)?;
            assert!(!result);

            // Test pin (which should overwrite)
            assert!(sdb.pin(&keys0, &vals1)?);
            let actuals = sdb.get(&keys0)?.unwrap();
            assert_eq!(actuals.len(), 1);
            let retrieved = actuals[0].as_any().downcast_ref::<BaseMatter>().unwrap();
            assert_eq!(retrieved.qb64(), matter1.qb64());

            // Test removal again
            assert!(sdb.rem(&keys0)?);
            let actuals = sdb.get(&keys0)?;
            assert!(actuals.is_none());

            // Test with string key instead of tuple
            let keys1 = ["beta.fish"];
            assert!(sdb.put(&keys1, &vals1)?);
            let actuals = sdb.get(&keys1)?.unwrap();
            assert_eq!(actuals.len(), 1);
            let retrieved = actuals[0].as_any().downcast_ref::<BaseMatter>().unwrap();
            assert_eq!(retrieved.qb64(), matter1.qb64());

            // Test removal of string key
            assert!(sdb.rem(&keys1)?);
            let actuals = sdb.get(&keys1)?;
            assert!(actuals.is_none());

            // Test missing entry
            let badkey = ["badkey"];
            let actuals = sdb.get(&badkey)?;
            assert!(actuals.is_none());
            // Test iteritems
            assert!(sdb.put(&keys0, &vals0)?);
            assert!(sdb.put(&keys1, &vals1)?);

            let prefix_key: [&str; 0] = [];

            let raw_items = sdb.get_item_iter(&prefix_key, true)?;

            // Convert raw items to more useful format for verification
            let items: Vec<(Vec<String>, String)> = raw_items
                .iter()
                .map(|(keys, vals)| {
                    // Convert keys to strings
                    let key_strs = keys
                        .iter()
                        .map(|k| String::from_utf8(k.clone()).unwrap())
                        .collect();

                    // Get the first Matter and convert to qb64
                    let matter = BaseMatter::from_qb64b(&mut vals.clone(), None).unwrap();
                    let qb64 = matter.qb64();

                    (key_strs, qb64)
                })
                .collect();

            // Check items match expected
            // Need to handle "alpha.dog" vs ["alpha", "dog"] based on separator
            let mut found_item1 = false;
            let mut found_item2 = false;

            for (key_parts, val) in items {
                if (key_parts[0] == "alpha" && key_parts[1] == "dog" && val == matter0.qb64())
                    || (key_parts.len() == 1
                        && key_parts[0] == "alpha.dog"
                        && val == matter0.qb64())
                {
                    found_item1 = true;
                }
                if (key_parts[0] == "beta" && key_parts[1] == "fish" && val == matter1.qb64())
                    || (key_parts.len() == 1
                        && key_parts[0] == "beta.fish"
                        && val == matter1.qb64())
                {
                    found_item2 = true;
                }
            }

            assert!(found_item1);
            assert!(found_item2);

            // Test prefix iteration
            assert!(sdb.put(&["b", "1"], &vals0)?);
            assert!(sdb.put(&["b", "2"], &vals1)?);
            assert!(sdb.put(&["c", "1"], &vals0)?);
            assert!(sdb.put(&["c", "2"], &vals1)?);

            let topkeys = ["b", ""];
            let raw_items = sdb.get_item_iter(&topkeys, true)?;

            // Convert and check just the b prefix items
            let items: Vec<(Vec<String>, String)> = raw_items
                .iter()
                .map(|(keys, vals)| {
                    let key_strs = keys
                        .iter()
                        .map(|k| String::from_utf8(k.clone()).unwrap())
                        .collect();

                    let matter = BaseMatter::from_qb64b(&mut vals.clone(), None).unwrap();
                    let qb64 = matter.qb64();

                    (key_strs, qb64)
                })
                .collect();

            // Check we have exactly the two b items
            assert_eq!(items.len(), 2);

            let mut found_b1 = false;
            let mut found_b2 = false;

            for (key_parts, val) in items {
                if (key_parts[0] == "b" && key_parts[1] == "1" && val == matter0.qb64()) {
                    found_b1 = true;
                }
                if (key_parts[0] == "b" && key_parts[1] == "2" && val == matter1.qb64()) {
                    found_b2 = true;
                }
            }

            assert!(found_b1);
            assert!(found_b2);
        }

        {
            // Test multiple klases with Dater, Seqner, Diger format
            let db_ref = Arc::new(&db);
            let sdb = CatCesrSuber::<BaseMatter>::new(
                db_ref.clone(),
                "bags.",
                vec![
                    "dater".to_string(),
                    "seqner".to_string(),
                    "diger".to_string(),
                ],
                None,
                false,
            )?;

            // Create test data
            let dater = Dater::from_dt(chrono::Utc::now());
            let datb = dater.qb64b();

            let seqner = Seqner::from_sn(20);
            let seqb = seqner.qb64b();
            assert_eq!(seqb, b"0AAAAAAAAAAAAAAAAAAAAAAU");

            let diger = Diger::from_ser("Hello Me Maties.".as_bytes(), None)?;
            let digb = diger.qb64b();

            // Test serialization and deserialization
            let vals: Vec<&dyn Matter> = vec![&dater, &seqner, &diger];

            // Use the CatCesrSuber methods directly through the base
            let valb = sdb.base.ser(&vals)?;
            assert_eq!(valb, [&datb[..], &seqb[..], &digb[..]].concat());

            // Test deserialization
            let des_result = sdb.base.des(&valb)?;
            let des_values = des_result;

            // Verify we got 3 Matters back and can be downcast to expected types
            assert_eq!(des_values.len(), 3);

            let des_dater = des_values[0].as_any().downcast_ref::<Dater>().unwrap();
            let des_seqner = des_values[1].as_any().downcast_ref::<Seqner>().unwrap();
            let des_diger = des_values[2].as_any().downcast_ref::<Diger>().unwrap();

            assert_eq!(des_dater.qb64b(), dater.qb64b());
            assert_eq!(des_seqner.qb64b(), seqner.qb64b());
            assert_eq!(des_diger.qb64b(), diger.qb64b());

            // Verify concat of all qb64b equals original serialized value
            let combined = [
                &des_dater.qb64b()[..],
                &des_seqner.qb64b()[..],
                &des_diger.qb64b()[..],
            ]
            .concat();
            assert_eq!(combined, valb);
        }

        {
            // Test Siger format
            let db_ref = Arc::new(&db);
            let sdb = CatCesrSuber::<BaseMatter>::new(
                db_ref.clone(),
                "pigs.",
                vec!["siger".to_string()],
                None,
                false,
            )?;

            // Create Siger
            let sig0 = "AACdI8OSQkMJ9r-xigjEByEjIua7LHH3AOJ22PQKqljMhuhcgh9nGRcKnsz5KvKd7K_H9-1298F4Id1DxvIoEmCQ";
            let val0 = Siger::from_qb64(sig0, None).unwrap();

            // Test put and get
            let keys = ["zeta", "cat"];
            assert!(sdb.put(&keys, &[&val0])?);

            let actuals = sdb.get(&keys)?.unwrap();
            assert_eq!(actuals.len(), 1);

            let actual_siger = actuals[0].as_any().downcast_ref::<Siger>().unwrap();
            assert_eq!(actual_siger.qb64(), val0.qb64());
        }

        Ok(())
    }
}
