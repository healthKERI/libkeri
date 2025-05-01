use crate::keri::db::dbing::LMDBer;
use crate::keri::db::subing::{SuberBase, SuberError, Utf8Codec, ValueCodec};
use std::sync::Arc;

pub struct DupSuber<'db, C: ValueCodec = Utf8Codec> {
    pub base: SuberBase<'db, C>,
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

    pub fn cnt<K: AsRef<[u8]>>(&self, keys: &[K]) -> Result<usize, SuberError> {
        let key = self.base.to_key(keys, false);
        self.base
            .db
            .cnt_vals(&self.base.sdb, &key)
            .map_err(SuberError::DBError)
    }

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
