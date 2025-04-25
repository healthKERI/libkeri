use crate::cesr::prefixer::Prefixer;
use crate::cesr::signing::Cipher;
use crate::keri::app::keeping::creators::Algos;
use crate::keri::core::filing::{BaseFiler, Filer, FilerDefaults};
use crate::keri::db::dbing::LMDBer;
use crate::keri::db::errors::DBError;
use crate::keri::db::koming::{Komer, SerialKind};
use crate::keri::db::subing::cesr::CesrSuber;
use crate::keri::db::subing::signer::CryptSignerSuber;
use crate::keri::db::subing::Suber;
use serde::{Deserialize, Serialize};
use std::iter::IntoIterator;
use std::path::PathBuf;
use std::sync::Arc;

/// Public key list with indexes and datetime created
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PubLot {
    /// List of fully qualified Base64 public keys
    #[serde(default)]
    pub pubs: Vec<String>,

    /// Rotation index of set of public keys at establishment event
    /// Index of key set at inception event is 0
    #[serde(default)]
    pub ridx: usize,

    /// Key index of starting key in key set in sequence wrt to all public keys
    /// Example if each set has 3 keys then ridx 2 has kidx of 2*3 = 6
    #[serde(default)]
    pub kidx: usize,

    /// Datetime in ISO8601 format of when key set was first created
    #[serde(default)]
    pub dt: String,
}

impl Default for PubLot {
    fn default() -> Self {
        Self {
            pubs: Vec::new(),
            ridx: 0,
            kidx: 0,
            dt: String::new(),
        }
    }
}

impl IntoIterator for PubLot {
    type Item = (String, serde_json::Value);
    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        let mut result = Vec::new();

        // Convert the struct to key-value pairs similar to Python's asdict
        result.push((
            "pubs".to_string(),
            serde_json::to_value(&self.pubs).unwrap(),
        ));
        result.push((
            "ridx".to_string(),
            serde_json::to_value(&self.ridx).unwrap(),
        ));
        result.push((
            "kidx".to_string(),
            serde_json::to_value(&self.kidx).unwrap(),
        ));
        result.push(("dt".to_string(), serde_json::to_value(&self.dt).unwrap()));

        result.into_iter()
    }
}

/// Prefix's public key situation (sets of public keys)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PreSit {
    /// Previous public key lot
    #[serde(default)]
    pub old: Option<PubLot>,

    /// Newly current public key lot
    #[serde(default)]
    pub new: PubLot,

    /// Next public key lot
    #[serde(default)]
    pub nxt: PubLot,
}

impl Default for PreSit {
    fn default() -> Self {
        Self {
            old: Some(PubLot::default()),
            new: PubLot::default(),
            nxt: PubLot::default(),
        }
    }
}

impl IntoIterator for PreSit {
    type Item = (String, serde_json::Value);
    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        let mut result = Vec::new();

        // Convert the struct to key-value pairs similar to Python's asdict
        result.push(("old".to_string(), serde_json::to_value(&self.old).unwrap()));
        result.push(("new".to_string(), serde_json::to_value(&self.new).unwrap()));
        result.push(("nxt".to_string(), serde_json::to_value(&self.nxt).unwrap()));

        result.into_iter()
    }
}

/// Prefix's parameters for creating new key pairs
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PrePrm {
    /// Prefix index for this keypair sequence
    #[serde(default)]
    pub pidx: usize,

    /// Algorithm used to create new key pairs (default is salty)
    #[serde(default = "default_algo")]
    pub algo: String,

    /// Salt used for salty algorithm
    #[serde(default)]
    pub salt: String,

    /// Default unique path stem for salty algorithm
    #[serde(default)]
    pub stem: String,

    /// Security tier for stretch index salty algorithm
    #[serde(default)]
    pub tier: String,
}

fn default_algo() -> String {
    Algos::Salty.to_string()
}

impl Default for PrePrm {
    fn default() -> Self {
        Self {
            pidx: 0,
            algo: Algos::Salty.to_string(),
            salt: String::new(),
            stem: String::new(),
            tier: String::new(),
        }
    }
}

impl IntoIterator for PrePrm {
    type Item = (String, serde_json::Value);
    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        let mut result = Vec::new();

        // Convert the struct to key-value pairs similar to Python's asdict
        result.push((
            "pidx".to_string(),
            serde_json::to_value(&self.pidx).unwrap(),
        ));
        result.push((
            "algo".to_string(),
            serde_json::to_value(&self.algo).unwrap(),
        ));
        result.push((
            "salt".to_string(),
            serde_json::to_value(&self.salt).unwrap(),
        ));
        result.push((
            "stem".to_string(),
            serde_json::to_value(&self.stem).unwrap(),
        ));
        result.push((
            "tier".to_string(),
            serde_json::to_value(&self.tier).unwrap(),
        ));

        result.into_iter()
    }
}

/// Prefix's public key set (list) at rotation index ridx
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PubSet {
    /// List of fully qualified Base64 public keys
    #[serde(default)]
    pub pubs: Vec<String>,
}

impl Default for PubSet {
    fn default() -> Self {
        Self { pubs: Vec::new() }
    }
}

impl IntoIterator for PubSet {
    type Item = (String, serde_json::Value);
    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        let mut result = Vec::new();

        // Convert the struct to key-value pairs similar to Python's asdict
        result.push((
            "pubs".to_string(),
            serde_json::to_value(&self.pubs).unwrap(),
        ));

        result.into_iter()
    }
}

/// Keeper struct for key pair storage (KS)
/// Sets up named sub databases for key pair storage.
/// Methods provide key pair creation, storage, and data signing.
pub struct Keeper<'db> {
    /// Base database
    lmdber: Arc<&'db LMDBer>, // The base LMDB database

    /// Global parameters for all prefixes
    /// Key is parameter label, Value is parameter
    pub gbls: Suber<'db>,

    /// Private keys database
    /// Key is public key (fully qualified qb64)
    /// Value is private key (fully qualified qb64)
    pub pris: CryptSignerSuber<'db>,

    /// Encrypted private keys database
    /// Key is identifier prefix (fully qualified qb64)
    /// Value is encrypted private key
    pub prxs: CesrSuber<'db, Cipher>,

    /// Next key digests database
    /// Key is identifier prefix (fully qualified qb64)
    /// Value is next key commitment (digest)
    pub nxts: CesrSuber<'db, Cipher>,

    /// Prefixes database
    /// Key is first public key in key sequence for a prefix (fully qualified qb64)
    /// Value is prefix or first public key (temporary) (fully qualified qb64)
    pub pres: CesrSuber<'db, Prefixer>,

    /// Prefix parameters database
    /// Key is identifier prefix (fully qualified qb64)
    /// Value is serialized parameter dict of public key parameters
    pub prms: Komer<'db, PrePrm>,

    /// Prefix situation database
    /// Key is identifier prefix (fully qualified qb64)
    /// Value is serialized parameter dict of public key situation
    pub sits: Komer<'db, PreSit>,

    /// Public keys database
    /// Key is prefix.ridx (rotation index as 32 char hex string)
    /// Value is serialized list of fully qualified public keys
    pub pubs: Komer<'db, PubSet>,
}

impl<'db> Filer for Keeper<'db> {
    fn defaults() -> FilerDefaults {
        BaseFiler::defaults()
    }

    #[cfg(target_os = "windows")]
    const TAIL_DIR_PATH: &'static str = "keri\\ks";
    #[cfg(not(target_os = "windows"))]
    const TAIL_DIR_PATH: &'static str = "keri/ks";

    #[cfg(target_os = "windows")]
    const ALT_TAIL_DIR_PATH: &'static str = ".keri\\ks";
    #[cfg(not(target_os = "windows"))]
    const ALT_TAIL_DIR_PATH: &'static str = ".keri/ks";

    const TEMP_PREFIX: &'static str = "keri_ks_";
}

impl<'db> Keeper<'db> {
    /// Maximum number of named databases
    pub const MAX_NAMED_DBS: u32 = 10;

    /// Create a new Keeper instance
    pub fn new(lmdber: Arc<&'db LMDBer>) -> Result<Self, DBError> {
        // Create the keeper instance
        let keeper = Keeper {
            lmdber: lmdber.clone(),
            // These will be initialized in the reopen method
            gbls: Suber::new(lmdber.clone(), "gbls.", None, false)
                .map_err(|e| DBError::DatabaseError(format!("SuberError: {}", e)))?,
            pris: CryptSignerSuber::new(lmdber.clone(), "pris.", None, false)
                .map_err(|e| DBError::DatabaseError(format!("SuberError: {}", e)))?,
            prxs: CesrSuber::new(lmdber.clone(), "prxs.", None, false)
                .map_err(|e| DBError::DatabaseError(format!("SuberError: {}", e)))?,
            nxts: CesrSuber::new(lmdber.clone(), "nxts.", None, false)
                .map_err(|e| DBError::DatabaseError(format!("SuberError: {}", e)))?,
            pres: CesrSuber::new(lmdber.clone(), "pres.", None, false)
                .map_err(|e| DBError::DatabaseError(format!("SuberError: {}", e)))?,
            prms: Komer::new(lmdber.clone(), "prms.", SerialKind::Json)
                .map_err(|e| DBError::DatabaseError(format!("SuberError: {}", e)))?,
            sits: Komer::new(lmdber.clone(), "sits.", SerialKind::Json)
                .map_err(|e| DBError::DatabaseError(format!("SuberError: {}", e)))?,
            pubs: Komer::new(lmdber.clone(), "pubs.", SerialKind::Json)
                .map_err(|e| DBError::DatabaseError(format!("SuberError: {}", e)))?,
        };

        Ok(keeper)
    }

    /// Check if database is opened
    pub fn opened(&self) -> bool {
        self.lmdber.opened()
    }

    /// Get name of database
    pub fn name(&self) -> String {
        self.lmdber.name()
    }

    /// Get database path
    pub fn path(&self) -> Option<PathBuf> {
        self.lmdber.path()
    }

    /// Close the database
    /// Check if database is temporary
    pub fn temp(&self) -> bool {
        self.lmdber.temp()
    }

    /// Create a key to access the pubs database with prefix and rotation index
    pub fn ri_key(pre: &str, ri: u64) -> String {
        format!("{}.{:032x}", pre, ri)
    }
}

impl<'db> Drop for Keeper<'db> {
    fn drop(&mut self) {
        // This is a no-op, as the LMDBer will be dropped automatically
        // and it has its own Drop implementation
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cesr::Parsable;
    use crate::Matter;

    #[test]
    fn test_keeper_basics() -> Result<(), DBError> {
        // Create a temporary Keeper instance
        let lmdber = LMDBer::builder().name("test_keeper").temp(true).build()?;

        // Create "seen." database
        assert_eq!(lmdber.name(), "test_keeper");
        assert!(lmdber.opened());
        let keeper = Keeper::new(Arc::new(&lmdber))?;
        assert!(keeper.opened());

        // Check it was created properly
        assert_eq!(keeper.name(), "test_keeper");
        assert!(keeper.opened());
        assert!(keeper.temp());

        // Check path exists
        let path = keeper.path().unwrap();
        assert!(path.exists());

        // Test dropping the keeper (should clean up if temp=true)
        drop(keeper);
        drop(lmdber);

        //TODO: Fix lmdber clean up dir on temp=true
        // assert!(!path.exists());

        Ok(())
    }

    #[test]
    fn test_keeper_subdb() -> Result<(), DBError> {
        // Create a temporary Keeper instance
        let mut lmdber = LMDBer::builder()
            .name("test_keeper_subdb")
            .temp(true)
            .build()?;

        // Create "seen." database
        assert_eq!(lmdber.name(), "test_keeper_subdb");
        assert!(lmdber.opened());
        let keeper = Keeper::new(Arc::new(&lmdber))?;

        // Test the gbls database
        let key = "aeid";
        let val = "BDzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc";

        keeper
            .gbls
            .put(&[key], &val.as_bytes())
            .map_err(|e| DBError::DatabaseError(format!("SuberError: {}", e)))?;

        let result: Option<Vec<u8>> = keeper
            .gbls
            .get(&[key])
            .map_err(|e| DBError::DatabaseError(format!("SuberError: {}", e)))?;
        assert!(result.is_some());

        let val_bytes = result.unwrap();
        let val_str = String::from_utf8(val_bytes).unwrap();
        assert_eq!(val_str, val);

        // Test the pres database
        let pub_key = b"BDzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc";
        let pre = Prefixer::from_qb64b(&mut pub_key.to_vec(), None).expect("Invalid prefix");

        keeper
            .pres
            .put(&[pub_key], &pre)
            .expect("Failed to put prefix");

        let result = keeper.pres.get(&[pub_key]).expect("Failed to get prefix");
        assert!(result.is_some());

        let retrieved_pre = result.unwrap();
        assert_eq!(retrieved_pre.qb64(), pre.qb64());

        // Test the prms Komer database (would require complete PrePrm implementation)
        // For brevity, we'll just check it exists
        let prms = PrePrm::default();
        let key = "prms.00000000000000000000000000000000";
        let result = keeper.prms.put(&[key], &prms).expect("Failed to put prms");
        assert!(result);

        let result = keeper.prms.get(&[key]).expect("Failed to get prms");
        assert!(result.is_some());
        assert_eq!(result.unwrap().pidx, 0);

        assert!(
            keeper
                .prms
                .cnt_all()
                .expect("there to be some values in the database")
                > 0
        );

        Ok(())
    }

    #[test]
    fn test_keeper_ri_key() {
        let pre = "EBfxc1UdwEMYy_g8Ldekf-aQEzBSkb3A5-vASBrV0qs4";
        let ri = 0;
        assert_eq!(
            Keeper::ri_key(pre, ri),
            "EBfxc1UdwEMYy_g8Ldekf-aQEzBSkb3A5-vASBrV0qs4.00000000000000000000000000000000"
        );

        let ri = 1;
        assert_eq!(
            Keeper::ri_key(pre, ri),
            "EBfxc1UdwEMYy_g8Ldekf-aQEzBSkb3A5-vASBrV0qs4.00000000000000000000000000000001"
        );
    }
}
