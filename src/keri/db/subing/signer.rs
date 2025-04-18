use std::sync::Arc;
use crate::cesr::Parsable;
use crate::cesr::verfer::Verfer;
use crate::errors::MatterError;
use crate::keri::db::dbing::LMDBer;
use crate::keri::db::subing::cesr::{CesrSuber, CesrSuberError};
use crate::keri::db::subing::SuberError;
use crate::Matter;

#[derive(Debug, thiserror::Error)]
pub enum SignerSuberError {
    #[error("CesrSuber error: {0}")]
    CesrSuberError(#[from] CesrSuberError),

    #[error("Matter error: {0}")]
    MatterError(#[from] MatterError),

    #[error("Invalid signer type")]
    InvalidSignerType,

    #[error("Verfer error: {0}")]
    VerferError(String),
}

pub trait SignerTrait: Matter + Parsable {
    fn with_transferable(qb64b: &[u8], transferable: bool) -> Result<Self, CesrSuberError>;
}

pub struct SignerSuber<'db, S: SignerTrait> {
    base: CesrSuber<'db, S>,
}

impl<'db, S: SignerTrait> SignerSuber<'db, S> {
    pub fn new(
        db: Arc<&'db LMDBer>,
        subkey: &str,
        sep: Option<u8>,
        verify: bool,
    ) -> Result<Self, SignerSuberError> {
        let base = CesrSuber::new(db, subkey, sep, verify)?;
        Ok(Self { base })
    }

    /// Gets Signer instance at keys
    ///
    /// # Arguments
    /// * `keys` - key bytes to be combined in order to form key. Last element of keys is verkey
    ///   used to determine .transferable for Signer
    ///
    /// # Returns
    /// * `Option<S>` - Signer instance with transferable property set correctly or None if no entry
    pub fn get<K: AsRef<[u8]>>(&self, keys: &[K]) -> Result<Option<S>, SignerSuberError> {
        if keys.is_empty() {
            return Err(SignerSuberError::CesrSuberError(CesrSuberError::SuberError(
                SuberError::EmptyKeys,
            )));
        }

        // Get raw value from database
        let key_result = self.base.get_full_item_iter(keys, false)?;
        if key_result.is_empty() {
            return Ok(None);
        }

        let (ikeys, raw_val) = &key_result[0];

        // Get the verkey (last element of keys)
        let mut verkey = if let Some(last_key) = ikeys.last() {
            last_key
        } else {
            return Err(SignerSuberError::CesrSuberError(CesrSuberError::SuberError(
                SuberError::EmptyKeys,
            )));
        };

        // Create Verfer from verkey to determine transferability
        let verfer = Verfer::from_qb64b(&mut verkey.clone(), None)?;
        let transferable = verfer.is_transferable();

        // Create Signer with the correct transferable property
        let signer = S::with_transferable(raw_val, transferable)?;

        Ok(Some(signer))
    }

    /// Returns iterator over items in the subdb whose key starts with the provided keys
    ///
    /// # Arguments
    /// * `keys` - Optional prefix keys to filter results
    /// * `topive` - If true, treat as partial key tuple from top branch
    ///
    /// # Returns
    /// * Vector of tuples containing (keys, signer instance)
    pub fn get_item_iter<K: AsRef<[u8]>>(
        &self,
        keys: &[K],
        topive: bool,
    ) -> Result<Vec<(Vec<Vec<u8>>, S)>, SignerSuberError> {
        let items = self.base.get_full_item_iter(keys, topive)?;
        let mut result = Vec::with_capacity(items.len());

        for (ikeys, val) in items {
            // Get verkey (last element of keys)
            let verkey = if let Some(last_key) = ikeys.last() {
                last_key
            } else {
                continue;
            };

            // Create Verfer from verkey to determine transferability
            let verfer = Verfer::from_qb64b(&mut verkey.clone(), None)?;
            let transferable = verfer.is_transferable();

            // Create Signer with the correct transferable property
            match S::with_transferable(&val, transferable) {
                Ok(signer) => result.push((ikeys, signer)),
                Err(e) => return Err(SignerSuberError::CesrSuberError(e)),
            }
        }

        Ok(result)
    }

    // Forward other methods to the base implementation
    pub fn put<K: AsRef<[u8]>>(&self, keys: &[K], val: &S) -> Result<bool, SignerSuberError> {
        Ok(self.base.put(keys, val)?)
    }

    pub fn trim<K: AsRef<[u8]>>(&self, keys: &[K], topive: bool) -> Result<bool, SignerSuberError> {
        Ok(self.base.trim(keys, topive)?)
    }

    pub fn cnt_all(&self) -> Result<usize, SignerSuberError> {
        Ok(self.base.cnt_all()?)
    }
}
