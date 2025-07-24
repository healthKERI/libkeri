mod habitat_record;
mod key_state_record;

use crate::cesr::counting::{ctr_dex_1_0, BaseCounter, Counter};
use crate::cesr::dater::Dater;
use crate::cesr::diger::Diger;
use crate::cesr::indexing::siger::Siger;
use crate::cesr::num_dex;
use crate::cesr::number::Number;
use crate::cesr::prefixer::Prefixer;
use crate::cesr::saider::Saider;
use crate::cesr::seqner::Seqner;
use crate::cesr::verfer::Verfer;
use crate::keri::core::eventing::Kever;
use crate::keri::core::filing::{BaseFiler, Filer, FilerDefaults};
use crate::keri::core::serdering::{Serder, SerderKERI};
use crate::keri::db::dbing::keys::dg_key;
use crate::keri::db::dbing::LMDBer;
use crate::keri::db::errors::DBError;
use crate::keri::db::koming::{Komer, SerialKind};
use crate::keri::db::subing::catcesr::CatCesrSuber;
use crate::keri::db::subing::catcesrioset::CatCesrIoSetSuber;
use crate::keri::db::subing::cesr::CesrSuber;
use crate::keri::db::subing::cesrioset::CesrIoSetSuber;
use crate::keri::db::subing::dup::DupSuber;
use crate::keri::db::subing::iodup::IoDupSuber;
use crate::keri::db::subing::on::OnSuber;
use crate::keri::db::subing::oniodup::OnIoDupSuber;
use crate::keri::db::subing::serder::SerderSuber;
use crate::keri::db::subing::{Suber, Utf8Codec};
use crate::keri::KERIError;
use crate::Matter;
use chrono::DateTime;
pub use habitat_record::HabitatRecord;
use indexmap::IndexSet;
pub use key_state_record::KeyStateRecord;
pub use key_state_record::StateEERecord;
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

/// EventSourceRecord tracks the source of an event (local or remote)
/// Keyed by dig (said) of serder of event
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventSourceRecord {
    /// True if local (protected), False if remote (unprotected)
    pub local: bool,
}

impl EventSourceRecord {
    /// Create a new EventSourceRecord with default local=true
    pub fn new() -> Self {
        EventSourceRecord { local: true }
    }

    /// Create a new EventSourceRecord with specified local value
    pub fn with_local(local: bool) -> Self {
        EventSourceRecord { local }
    }

    /// Convert the record to a hashmap for serialization
    pub fn to_map(&self) -> HashMap<String, bool> {
        let mut map = HashMap::new();
        map.insert("local".to_string(), self.local);
        map
    }

    /// Create from a hashmap after deserialization
    pub fn from_map(map: &HashMap<String, bool>) -> Option<Self> {
        map.get("local").map(|&local| EventSourceRecord { local })
    }
}

impl Default for EventSourceRecord {
    fn default() -> Self {
        Self::new()
    }
}

impl IntoIterator for EventSourceRecord {
    type Item = (String, bool);
    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        vec![("local".to_string(), self.local)].into_iter()
    }
}

/// Service Endpoint Record with url for endpoint of a given scheme
///
/// The eid is usually a nontransferable identifier when its used for roles
/// witness or watcher but may be transferable for other roles such as controller,
/// judge, juror, public watcher, or registrar.
///
/// Database Keys are (eid, scheme) where eid is service endpoint identifier
/// (qb64 prefix) and scheme is the url protocol scheme (tcp, https).
///
/// A loc reply message is required from which the values of this
/// database record are extracted. route is /loc/scheme Uses enact-anul model
/// To nullify endpoint set url field to empty.
///
/// An end authorization reply message is also required to authorize the eid as
/// endpoint provider for cid at role. See EndpointRecord
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocationRecord {
    /// Full url including host:port/path?query scheme is optional
    pub url: String,
}

impl LocationRecord {
    /// Create a new LocationRecord
    pub fn new(url: String) -> Self {
        Self { url }
    }

    /// Check if the endpoint is nullified (empty url)
    pub fn is_nullified(&self) -> bool {
        self.url.is_empty()
    }

    /// Convert to HashMap for iteration/serialization compatibility
    pub fn to_map(&self) -> HashMap<String, String> {
        let mut map = HashMap::new();
        map.insert("url".to_string(), self.url.clone());
        map
    }
}

impl IntoIterator for LocationRecord {
    type Item = (String, String);
    type IntoIter = std::collections::hash_map::IntoIter<String, String>;

    fn into_iter(self) -> Self::IntoIter {
        self.to_map().into_iter()
    }
}

/// Service Endpoint ID (SEID) Record with fields and keys to manage endpoints by
/// cid, role, and eid. Serves as aggregation mechanism for authorization and other
/// functions such as UX naming with regards the endpoint.
///
/// The namespace is a tree of branches with each leaf at a
/// specific (cid, role, eid). Retrieval by branch returns groups of leaves as
/// appropriate for a cid branch or cid.role branch.
/// Database Keys are (cid, role, eid) where cid is attributable controller identifier
/// (qb64 prefix) that has role(s) such as watcher, witness etc and eid is the
/// identifier of the controller acting in a role i.e. watcher identifier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndpointRecord {
    /// AuthZ via reply message
    /// - `Some(true)` means eid is allowed as controller of endpoint in role
    /// - `Some(false)` means eid is disallowed as controller of endpoint in role  
    /// - `None` means eid is neither allowed or disallowed (no reply msg)
    pub allowed: Option<bool>,

    /// AuthZ via expose message
    /// - `Some(true)` means eid is enabled as controller of endpoint in role
    /// - `Some(false)` means eid is disabled as controller of endpoint in role
    /// - `None` means eid is neither enabled or disabled (no expose msg)
    pub enabled: Option<bool>,

    /// Optional user friendly name for eid in role
    pub name: String,
}

impl EndpointRecord {
    /// Create a new EndpointRecord with default values
    pub fn new() -> Self {
        Self {
            allowed: None,
            enabled: None,
            name: String::new(),
        }
    }

    /// Create a new EndpointRecord with specified values
    pub fn with_values(allowed: Option<bool>, enabled: Option<bool>, name: String) -> Self {
        Self {
            allowed,
            enabled,
            name,
        }
    }

    /// Check if endpoint is allowed (authorized via reply message)
    pub fn is_allowed(&self) -> Option<bool> {
        self.allowed
    }

    /// Check if endpoint is enabled (authorized via expose message)
    pub fn is_enabled(&self) -> Option<bool> {
        self.enabled
    }

    /// Set allowed status (add/cut model)
    pub fn set_allowed(&mut self, allowed: bool) {
        self.allowed = Some(allowed);
    }

    /// Set enabled status  
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = Some(enabled);
    }

    /// Set user friendly name
    pub fn set_name(&mut self, name: String) {
        self.name = name;
    }

    /// Convert to HashMap for iteration/serialization compatibility
    pub fn to_map(&self) -> HashMap<String, serde_json::Value> {
        let mut map = HashMap::new();
        map.insert("allowed".to_string(), serde_json::Value::from(self.allowed));
        map.insert("enabled".to_string(), serde_json::Value::from(self.enabled));
        map.insert(
            "name".to_string(),
            serde_json::Value::String(self.name.clone()),
        );
        map
    }
}

impl Default for EndpointRecord {
    fn default() -> Self {
        Self::new()
    }
}

impl IntoIterator for EndpointRecord {
    type Item = (String, serde_json::Value);
    type IntoIter = std::collections::hash_map::IntoIter<String, serde_json::Value>;

    fn into_iter(self) -> Self::IntoIter {
        self.to_map().into_iter()
    }
}

// Database key types for organizing records
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LocationKey {
    pub eid: String,    // service endpoint identifier (qb64 prefix)
    pub scheme: String, // url protocol scheme (tcp, https)
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EndpointKey {
    pub cid: String,  // attributable controller identifier (qb64 prefix)
    pub role: String, // role such as watcher, witness
    pub eid: String,  // identifier of the controller acting in role
}

impl LocationKey {
    pub fn new(eid: String, scheme: String) -> Self {
        Self { eid, scheme }
    }
}

impl EndpointKey {
    pub fn new(cid: String, role: String, eid: String) -> Self {
        Self { cid, role, eid }
    }
}

/// Baser struct for key event log and escrow storage (DB)
/// Sets up named sub databases for key event logs and escrow storage.
pub struct Baser<'db> {
    /// Base database
    lmdber: Arc<&'db LMDBer>, // The base LMDB database

    pub prefixes: IndexSet<String>,
    pub groups: IndexSet<String>,
    pub kevers: HashMap<String, Kever<'db>>,

    /// habitat application state keyed by habitat name, includes prefix
    pub habs: Komer<'db, HabitatRecord>,

    /// habitat name database mapping (domain,name) as key to Prefixer
    pub names: Suber<'db>,

    /// .evts is named sub DB whose values are serialized key events
    ///     dgKey
    ///     DB is keyed by identifier prefix plus digest of serialized event
    ///     Only one value per DB key is allowed
    pub evts: Suber<'db>,

    /// .fels is named sub DB of first seen event logs (FEL) as indices that map
    ///    first seen ordinal number to digests.
    ///    Actual serialized key events are stored in .evts by SAID digest
    ///    This indexes events in first 'seen' accepted order for replay and
    ///    cloning of event log.
    ///    Uses first seen order number or fn.
    ///    fnKey
    ///    DB is keyed by identifier prefix plus monotonically increasing first
    ///    seen order number fn.
    ///    Value is digest of serialized event used to lookup event in .evts sub DB
    ///    Only one value per DB key is allowed.
    ///    Provides append only ordering of accepted first seen events.
    pub fels: OnSuber<'db>,

    /// .kels is named sub DB of key event logs as indices that map sequence numbers
    ///     to serialized key event digests.
    ///     Actual serialized key events are stored in .evts by SAID digest
    ///     Uses sequence number or sn.
    ///     snKey
    ///     Values are digests used to lookup event in .evts sub DB
    ///     DB is keyed by identifier prefix plus sequence number of key event
    ///     More than one value per DB key is allowed
    pub kels: OnIoDupSuber<'db, Utf8Codec>,

    /// .fons is named subDB CesrSuber
    ///     Uses digest
    ///     dgKey
    ///     Maps prefix and digest to fn value (first seen ordinal number) of
    ///     the associated event. So one used pre and event digest, get its fn here
    ///     and then use fn to fetch event from .evnts by fn from .fels.
    ///     This ensures that any event looked up this way was first seen at
    ///     some point in time even if later superseded by a recovery rotation.
    ///     Whereas direct lookup in .evts could be escrowed events that may
    ///     never have been accepted as first seen.
    ///     CesrSuber(db=self, subkey='fons.', klas=core.Number)
    pub fons: CesrSuber<'db, Number>,

    /// .esrs is named sub DB instance of Komer of EventSourceRecord
    ///      dgKey
    ///      DB is keyed by identifier prefix plus digest (said) of serialized event
    ///      Value is serialized instance of EventSourceRecord dataclass.
    ///      Only one value per DB key is allowed.
    ///      Keeps track of the source of the event. When .local is Truthy the
    ///      event was sourced in a protected way such as being generated
    ///      locally or via a protected path. When .local is Falsey the event was
    ///      NOT sourced in a protected way. The value of .local determines what
    ///      validation logic to run on the event. This database is used to track
    ///      the source when processing escrows that would otherwise be decoupled
    ///      from the original source of the event.
    pub esrs: Komer<'db, EventSourceRecord>,

    /// .dtss is named sub DB of datetime stamp strings in ISO 8601 format of
    ///      the datetime when the event was first escrosed and then later first
    ///      seen by log. Used for escrows timeouts and extended validation.
    ///      dgKey
    ///      DB is keyed by identifier prefix plus digest of serialized event
    ///      Value is ISO 8601 datetime stamp bytes
    pub dtss: DupSuber<'db>,

    /// .sdts (sad date-time-stamp) named subDB instance of CesrSuber that
    ///     maps SAD SAID to Dater instance's CESR serialization of
    ///     ISO-8601 datetime
    ///     key = said (bytes) of sad, val = dater.qb64b
    pub sdts: CesrSuber<'db, Dater>,

    /// .rpys (replys) named subDB instance of SerderSuber that maps said of
    ///     reply message (versioned SAD) to serialization of that reply message.
    ///     key is said bytes, val is Serder.raw bytes of reply 'rpy' message
    pub rpys: SerderSuber<'db, SerderKERI>,

    /// .ssgs (sad trans indexed sigs) named subDB instance of CesrIoSetSuber
    ///     that maps keys quadruple (saider.qb64, prefixer.qb64, seqner.q64,
    ///     diger.qb64) to val Siger of trans id signature. Where: saider is
    ///     said of SAD and prefixer, seqner, and diger indicate the key state
    ///     est event for signer or reply SAD. Each key may
    ///     have a set of vals in insertion order one for each signer of the sad.
    ///     key = join (saider.qb64b, prefixer.qb64b, seqner.qb64b, diger.qb64b)
    ///     (bytes)  val = siger.qb64b
    pub ssgs: CatCesrIoSetSuber<'db, Siger>,

    /// .scgs (sad nontrans cigs) named subDB instance of CatCesrIoSetSuber
    ///     that maps said of SAD to couple (Verfer, Cigar) for nontrans signer.
    ///     For nontrans qb64 of Verfer is same as Prefixer.
    ///     Each key may have a set of vals in insertion order one for each
    ///     nontrans signer of the sad.
    ///     key = said (bytes) of SAD, val = cat of (verfer.qb64, cigar.qb64b)
    pub scgs: CatCesrIoSetSuber<'db, Verfer>,

    /// .rpes (reply escrows) named subDB instance of CesrIoSetSuber that
    ///     maps routes of reply (versioned SAD) to single Saider of that
    ///     reply msg.
    ///     Routes such as '/end/role/' and '/loc/scheme'
    ///     key is route bytes, vals = saider.qb64b of reply 'rpy' msg
    pub rpes: CesrIoSetSuber<'db, Saider>,

    /// .aess is named sub DB of authorizing event source seal couples
    ///      that map digest to seal source couple of authorizer's
    ///      (delegator or issuer) event. Each couple is a concatenation of full
    ///      qualified items, snu+dig of the authorizing (delegating or issuing)
    ///      source event.
    ///      dgKey
    ///      Values are couples used to lookup authorizer's source event in
    ///      .kels sub DB
    ///      DB is keyed by identifier prefix plus digest of key event
    ///      Only one value per DB key is allowed
    pub aess: Suber<'db>,

    /// .sigs is named sub DB of fully qualified indexed event signatures
    ///      dgKey
    ///      DB is keyed by identifier prefix plus digest of serialized event
    ///      More than one value per DB key is allowed
    pub sigs: DupSuber<'db>,

    ///  .wigs is named sub DB of indexed witness signatures of event that may
    ///      come directly or derived from a witness receipt message.
    ///      Witnesses always have nontransferable identifier prefixes.
    ///      The index is the offset of the witness into the witness list
    ///      of the most recent establishment event wrt the receipted event.
    ///      dgKey
    ///      DB is keyed by identifier prefix plus digest of serialized event
    ///      More than one value per DB key is allowed
    pub wigs: DupSuber<'db>,

    /// Insertion order set of witnesses qb64 prefix
    pub wits: IoDupSuber<'db>,

    /// .rcts is named sub DB of event receipt couplets from nontransferable
    ///     signers.
    ///     These are endorsements from nontrasferable signers who are not witnesses
    ///     May be watchers or other
    ///     Each couple is concatenation of fully qualified items.
    ///     These are: non-transferale prefix plus non-indexed event signature
    ///     by that prefix.
    ///     dgKey
    ///     DB is keyed by identifier prefix plus digest of serialized event
    ///     More than one value per DB key is allowed
    pub rcts: DupSuber<'db>,

    /// .vrcs is named sub DB of event validator receipt quadruples from transferable
    ///     signers. Each quadruple is concatenation of  four fully qualified items
    ///     of validator. These are: transferable prefix, plus latest establishment
    ///     event sequence number plus latest establishment event digest,
    ///     plus indexed event signature.
    ///     These are endorsements by transferable AIDs that are not the controller
    ///     may be watchers or others.
    ///     When latest establishment event is multisig then there will
    ///     be multiple quadruples one per signing key, each a dup at same db key.
    ///     dgKey
    ///     DB is keyed by identifier prefix plus digest of serialized event
    ///     More than one value per DB key is allowed
    pub vrcs: DupSuber<'db>,

    /// Prefix situation database
    /// Key is identifier prefix (fully qualified qb64)
    /// Value is serialized parameter dict of public key situation
    pub states: Komer<'db, KeyStateRecord>,

    pub locs: Komer<'db, LocationRecord>,

    pub ends: Komer<'db, EndpointRecord>,

    pub eans: CesrSuber<'db, Saider>,

    pub lans: CesrSuber<'db, Saider>,

    pub pses: IoDupSuber<'db>,
}

impl<'db> Filer for Baser<'db> {
    fn defaults() -> FilerDefaults {
        BaseFiler::defaults()
    }

    #[cfg(target_os = "windows")]
    const TAIL_DIR_PATH: &'static str = "keri\\db";
    #[cfg(not(target_os = "windows"))]
    const TAIL_DIR_PATH: &'static str = "keri/db";

    #[cfg(target_os = "windows")]
    const ALT_TAIL_DIR_PATH: &'static str = ".keri\\db";
    #[cfg(not(target_os = "windows"))]
    const ALT_TAIL_DIR_PATH: &'static str = ".keri/db";

    const TEMP_PREFIX: &'static str = "keri_db_";
}

impl<'db> Baser<'db> {
    /// Maximum number of named databases
    pub const MAX_NAMED_DBS: u32 = 10;

    /// Create a new Keeper instance
    pub fn new(lmdber: Arc<&'db LMDBer>) -> Result<Self, DBError> {
        // Create the keeper instance
        let baser = Baser {
            lmdber: lmdber.clone(),
            prefixes: IndexSet::new(),
            groups: IndexSet::new(),
            kevers: HashMap::new(),

            // Initialize the evts sub database
            evts: Suber::new(lmdber.clone(), "evts.", None, false)
                .map_err(|e| DBError::DatabaseError(format!("SuberError: {}", e)))?,

            // Initialize the fels sub database
            fels: OnSuber::new(lmdber.clone(), "fels.", None, false)
                .map_err(|e| DBError::DatabaseError(format!("SuberError: {}", e)))?,

            // Initialize the kels sub database
            kels: OnIoDupSuber::new(lmdber.clone(), "kels.", None, false)
                .map_err(|e| DBError::DatabaseError(format!("SuberError: {}", e)))?,

            // Initialize the fons sub database
            fons: CesrSuber::<Number>::new(lmdber.clone(), "fons.", None, false)
                .map_err(|e| DBError::DatabaseError(format!("SuberError: {}", e)))?,

            // Initialize the esrs sub database
            esrs: Komer::new(lmdber.clone(), "esrs.", SerialKind::Json)
                .map_err(|e| DBError::DatabaseError(format!("SuberError: {}", e)))?,

            // Initialize the dtss sub database
            dtss: DupSuber::new(lmdber.clone(), "dtss.", None, false)
                .map_err(|e| DBError::DatabaseError(format!("SuberError: {}", e)))?,

            rpys: SerderSuber::new(lmdber.clone(), "rpys", None, false)
                .map_err(|e| DBError::DatabaseError(format!("SuberError: {}", e)))?,

            sdts: CesrSuber::new(lmdber.clone(), "sdts", None, false)
                .map_err(|e| DBError::DatabaseError(format!("SuberError: {}", e)))?,

            ssgs: CatCesrIoSetSuber::new(
                lmdber.clone(),
                "ssgs.",
                vec!["siger".to_string()],
                None,
                false,
            )
            .map_err(|e| DBError::DatabaseError(format!("SuberError: {}", e)))?,

            scgs: CatCesrIoSetSuber::new(
                lmdber.clone(),
                "scgs.",
                vec!["verfer".to_string(), "cigar".to_string()],
                None,
                false,
            )
            .map_err(|e| DBError::DatabaseError(format!("SuberError: {}", e)))?,

            rpes: CesrIoSetSuber::new(lmdber.clone(), "rpes.", None, false)
                .map_err(|e| DBError::DatabaseError(format!("SuberError: {}", e)))?,

            // Initialize the aess sub database
            aess: Suber::new(lmdber.clone(), "aess.", None, false)
                .map_err(|e| DBError::DatabaseError(format!("SuberError: {}", e)))?,

            // Initialize the sigs sub database
            sigs: DupSuber::new(lmdber.clone(), "sigs.", None, false)
                .map_err(|e| DBError::DatabaseError(format!("SuberError: {}", e)))?,

            // Initialize the wigs sub database
            wigs: DupSuber::new(lmdber.clone(), "wigs.", None, false)
                .map_err(|e| DBError::DatabaseError(format!("SuberError: {}", e)))?,

            // Initialize the wits sub database
            wits: IoDupSuber::new(lmdber.clone(), "wits.", None, false)
                .map_err(|e| DBError::DatabaseError(format!("SuberError: {}", e)))?,

            // Initialize the wits sub database
            rcts: DupSuber::new(lmdber.clone(), "rcts.", None, false)
                .map_err(|e| DBError::DatabaseError(format!("SuberError: {}", e)))?,

            // Initialize the wits sub database
            vrcs: DupSuber::new(lmdber.clone(), "vrcs.", None, false)
                .map_err(|e| DBError::DatabaseError(format!("SuberError: {}", e)))?,

            // Initialize the states sub database
            states: Komer::new(lmdber.clone(), "stts.", SerialKind::Json)
                .map_err(|e| DBError::DatabaseError(format!("SuberError: {}", e)))?,

            ends: Komer::new(lmdber.clone(), "stts.", SerialKind::Json)
                .map_err(|e| DBError::DatabaseError(format!("SuberError: {}", e)))?,

            locs: Komer::new(lmdber.clone(), "stts.", SerialKind::Json)
                .map_err(|e| DBError::DatabaseError(format!("SuberError: {}", e)))?,

            habs: Komer::new(lmdber.clone(), "habs.", SerialKind::Json)
                .map_err(|e| DBError::DatabaseError(format!("SuberError: {}", e)))?,

            names: Suber::new(lmdber.clone(), "names.", None, false)
                .map_err(|e| DBError::DatabaseError(format!("SuberError: {}", e)))?,

            eans: CesrSuber::new(lmdber.clone(), "eans.", None, false)
                .map_err(|e| DBError::DatabaseError(format!("SuberError: {}", e)))?,

            lans: CesrSuber::new(lmdber.clone(), "lans.", None, false)
                .map_err(|e| DBError::DatabaseError(format!("SuberError: {}", e)))?,

            pses: IoDupSuber::new(lmdber.clone(), "pses.", None, false)
                .map_err(|e| DBError::DatabaseError(format!("SuberError: {}", e)))?,
        };

        Ok(baser)
    }
    pub fn get_ke_last<K>(&self, key: K) -> Result<Option<String>, KERIError>
    where
        K: AsRef<[u8]>,
    {
        // Use the kels OnIoDupSuber to get the last inserted duplicate value
        match self.kels.get_io_dup_val_last::<K, Vec<u8>>(&[key]) {
            Ok(Some(val_bytes)) => {
                // Convert bytes to String (assuming UTF-8 encoded digest)
                match String::from_utf8(val_bytes) {
                    Ok(digest) => Ok(Some(digest)),
                    Err(e) => Err(KERIError::DeserializationError(format!(
                        "Failed to decode digest as UTF-8: {}",
                        e
                    ))),
                }
            }
            Ok(None) => Ok(None),
            Err(e) => {
                // Convert SuberError to DBError - adjust this based on your DBError enum
                Err(KERIError::DatabaseError(format!("SuberError: {}", e)))
            }
        }
    }

    pub fn get_evt<K>(&self, key: K) -> Result<Option<Vec<u8>>, KERIError>
    where
        K: AsRef<[u8]>,
    {
        // Convert the key to the format expected by the evts database
        let db_key = self.evts.to_key(&[key], false);

        // Call the LMDBer's get_val method directly
        self.lmdber
            .get_val(&self.evts.base.sdb, &db_key)
            .map_err(|e| KERIError::DatabaseError(format!("LMDBer error: {}", e)))
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

    pub fn fully_witnessed(&self, serder: &SerderKERI) -> bool {
        let preb = serder.preb().unwrap_or_default();
        let said = serder.said().unwrap_or_default();

        let key = dg_key(preb, said);
        match self.wigs.get::<_, Vec<u8>>(&[&key]) {
            Ok(wigs) => {
                let pre = serder.pre().unwrap();
                let kever = &self.kevers[&pre];
                let toad = kever.toader().unwrap().num();
                !wigs.len() < toad as usize
            }
            Err(_) => false,
        }
    }

    pub fn fetch_all_sealing_event_by_event_seal(
        &self,
        _pre: &str,
        _anchor: &str,
    ) -> Result<bool, DBError> {
        Ok(false)
    }

    /// Returns an iterator of first seen event messages with attachments for the
    /// identifier prefix `pre` starting at first seen order number, `fn_num`.
    /// Essentially a replay in first seen order with attachments.
    ///
    /// # Parameters
    /// * `pre` - Identifier prefix as string
    /// * `fn_num` - Optional first seen number to resume replay. Default is 0
    ///
    /// # Returns
    /// * `Result<Vec<Vec<u8>>, DBError>` - Collection of messages with prefix `pre` starting at `fn_num`
    pub fn clone_pre_iter(&self, pre: &str, fn_num: Option<u64>) -> Result<Vec<Vec<u8>>, DBError> {
        let start_fn = fn_num.unwrap_or(0);
        let mut msgs = Vec::new();

        // We need to get items from the fels database for the given prefix
        // starting at the specified first seen ordinal number
        let key_prefix = pre.as_bytes(); // Prefix for key search

        // Get all items with this prefix
        let mut items = Vec::new();

        // Use the low-level interface to get items from the fels database
        let on_items: Vec<(Vec<Vec<u8>>, u64, Vec<u8>)> = self
            .fels
            .get_on_item_iter(&[&key_prefix], start_fn as u32)
            .map_err(|e| DBError::DatabaseError(format!("Error getting items: {}", e)))?;

        for (ckey, cn, cval) in on_items {
            // Check if the key starts with our prefix
            if ckey.starts_with(&[pre.as_bytes().to_vec()]) && cn >= start_fn {
                // Convert the digest value to a string
                let dig = String::from_utf8_lossy(&cval).to_string();
                items.push((ckey.to_vec(), cn, dig));
            }
        }

        // Now process each item to get the serialized message
        for (_, fn_num, dig) in items {
            match self.clone_evt_msg(pre, fn_num, &dig) {
                Ok(msg) => msgs.push(msg),
                Err(_) => continue, // Skip this event if there's an error, as in Python implementation
            }
        }

        Ok(msgs)
    }
    /// Recursively clone delegation chain from AID of Kever if one exists.
    ///
    /// This method yields messages in the correct order: first the delegator's
    /// delegation chain (if any), then all events from the delegator's key event log.
    ///
    /// # Parameters
    /// * `kever` - Kever from which to clone the delegator's AID
    ///
    /// # Returns
    /// * `Result<Vec<Vec<u8>>, DBError>` - Collection of messages representing the delegation chain
    pub fn clone_delegation(&self, kever: &Kever<'db>) -> Result<Vec<Vec<u8>>, DBError> {
        let mut msgs = Vec::new();

        // Check if this kever is delegated and has a delegator in our kevers
        if kever.delegated {
            if let Some(ref delpre) = kever.delpre {
                if let Some(dkever) = self.kevers.get(delpre) {
                    // Recursively clone the delegator's delegation chain first
                    let delegator_msgs = self.clone_delegation(dkever)?;
                    msgs.extend(delegator_msgs);

                    // Then clone all events from the delegator's prefix starting from fn=0
                    let delegator_events = self.clone_pre_iter(delpre, Some(0))?;
                    msgs.extend(delegator_events);
                }
            }
        }

        Ok(msgs)
    }

    /// Clones Event as Serialized CESR Message with Body and attached Foot
    ///
    /// # Parameters
    /// * `pre` - Identifier prefix of event
    /// * `fn_num` - First seen number (ordinal) of event
    /// * `dig` - Digest of event
    ///
    /// # Returns
    /// * `Result<Vec<u8>, DBError>` - Message body with attachments
    pub fn clone_evt_msg(&self, pre: &str, fn_num: u64, dig: &str) -> Result<Vec<u8>, DBError> {
        // Initialize message and attachments
        let mut msg = Vec::<u8>::new(); // message
        let mut atc = Vec::<u8>::new(); // attachments

        // Get the event message
        let dg_key = dg_key(pre, dig);
        let raw = self
            .evts
            .get::<_, Vec<u8>>(&[&dg_key])
            .map_err(|_| DBError::MissingEntryError(format!("Missing event for dig={}.", dig)))?;

        // Extend message with raw event data
        msg.extend_from_slice(&raw.unwrap_or_default());

        // Add indexed signatures to attachments
        let sigs = self
            .sigs
            .get::<_, Vec<u8>>(&[&dg_key])
            .map_err(|_| DBError::MissingEntryError(format!("Missing sigs for dig={}.", dig)))?;

        // Add counter for controller indexed signatures
        let counter = BaseCounter::from_code_and_count(
            Some(ctr_dex_1_0::CONTROLLER_IDX_SIGS),
            Some(sigs.len() as u64),
            Some("1.0"),
        )
        .unwrap()
        .qb64b();
        atc.extend_from_slice(&counter);

        // Add each signature to attachments
        for sig in sigs {
            atc.extend_from_slice(&sig);
        }

        // Add indexed witness signatures to attachments if they exist
        if let Ok(wigs) = self.wigs.get::<_, Vec<u8>>(&[&dg_key]) {
            if !wigs.is_empty() {
                // Add counter for witness indexed signatures
                let counter = BaseCounter::from_code_and_count(
                    Some(ctr_dex_1_0::WITNESS_IDX_SIGS),
                    Some(wigs.len() as u64),
                    Some("1.0"),
                )
                .unwrap()
                .qb64b();
                atc.extend_from_slice(&counter);

                // Add each witness signature to attachments
                for wig in wigs {
                    atc.extend_from_slice(&wig);
                }
            }
        }

        // Add authorizer (delegator/issuer) source seal event couple to attachments
        if let Ok(Some(couple)) = self.aess.get::<_, Option<Vec<u8>>>(&[&dg_key]) {
            // Add counter for seal source couples
            let counter = BaseCounter::from_code_and_count(
                Some(ctr_dex_1_0::SEAL_SOURCE_COUPLES),
                Some(1),
                Some("1.0"),
            )
            .unwrap()
            .qb64b();
            atc.extend_from_slice(&counter);
            atc.extend_from_slice(&couple.unwrap());
        }

        // Add trans endorsement quadruples to attachments (not controller)
        if let Ok(quads) = self.vrcs.get::<_, Vec<u8>>(&[&dg_key]) {
            if !quads.is_empty() {
                // Add counter for trans receipt quadruples
                let counter = BaseCounter::from_code_and_count(
                    Some(ctr_dex_1_0::TRANS_RECEIPT_QUADRUPLES),
                    Some(quads.len() as u64),
                    Some("1.0"),
                )
                .unwrap()
                .qb64b();
                atc.extend_from_slice(&counter);

                // Add each quadruple to attachments
                for quad in quads {
                    atc.extend_from_slice(&quad);
                }
            }
        }

        // Add nontrans endorsement couples to attachments (not witnesses)
        if let Ok(coups) = self.rcts.get::<_, Vec<u8>>(&[&dg_key]) {
            if !coups.is_empty() {
                // Add counter for non-trans receipt couples
                let counter = BaseCounter::from_code_and_count(
                    Some(ctr_dex_1_0::NON_TRANS_RECEIPT_COUPLES),
                    Some(coups.len() as u64),
                    Some("1.0"),
                )
                .unwrap()
                .qb64b();
                atc.extend_from_slice(&counter);

                // Add each couple to attachments
                for coup in coups {
                    atc.extend_from_slice(&coup);
                }
            }
        }

        // Add first seen replay couple to attachments
        let dts = self.dtss.get::<_, Vec<u8>>(&[&dg_key]).map_err(|_| {
            DBError::MissingEntryError(format!("Missing datetime for dig={}.", dig))
        })?;

        // Add counter for first seen replay couples
        let counter = BaseCounter::from_code_and_count(
            Some(ctr_dex_1_0::FIRST_SEEN_REPLAY_COUPLES),
            Some(1),
            Some("1.0"),
        )
        .unwrap()
        .qb64b();
        atc.extend_from_slice(&counter);

        // Add first seen number
        let fn_bytes = Number::from_num_and_code(&BigUint::from(fn_num), num_dex::HUGE)
            .unwrap()
            .qb64b();
        atc.extend_from_slice(&fn_bytes);

        // Add datetime
        let dt = DateTime::parse_from_rfc3339(&String::from_utf8_lossy(&dts[0]))
            .map_err(|e| DBError::ValueError(format!("{}", e)))?;
        let dater = Dater::from_dt(DateTime::from(dt)).qb64b();
        atc.extend_from_slice(&dater);

        // Check if attachments size is valid (multiple of 4)
        if atc.len() % 4 != 0 {
            return Err(DBError::ValueError(format!(
                "Invalid attachments size={}, nonintegral quadlets.",
                atc.len()
            )));
        }

        // Prepend pipelining counter to attachments
        let pcnt = BaseCounter::from_code_and_count(
            Some(ctr_dex_1_0::ATTACHMENT_GROUP),
            Some((atc.len() / 4) as u64),
            Some("1.0"),
        )
        .unwrap()
        .qb64b();
        msg.extend_from_slice(&pcnt);

        // Add attachments to message
        msg.extend_from_slice(&atc);

        Ok(msg)
    }

    /// Returns iterator of all (pre, fn, dig) triples in first seen order for
    /// all events for all prefixes in database. Items are sorted by
    /// fnKey(pre, fn) where fn is first seen order number int.
    /// Returns all First Seen Event Logs FELs.
    ///
    /// Returned items are triples of (pre, fn, dig): Where pre is identifier prefix,
    /// fn is first seen order number int and dig is event digest for lookup
    /// in .evts sub db.
    ///
    /// # Returns
    /// * `Result<Vec<(String, u64, String)>, DBError>` - Collection of (prefix, fn, digest) triples
    pub fn get_fel_item_all_pre_iter(&self) -> Result<Vec<(String, u64, String)>, DBError> {
        let mut items = Vec::new();
        // Get all items from the fels database starting from the beginning (empty key)
        let on_items: Vec<(Vec<Vec<u8>>, u64, Vec<u8>)> = self
            .fels
            .get_on_item_iter(&[b""], 0)
            .map_err(|e| DBError::DatabaseError(format!("Error getting all FEL items: {}", e)))?;

        for (ckey, cn, cval) in on_items {
            // Extract the prefix from the composite key
            // The key format is typically [prefix_bytes, fn_bytes]
            // We need to extract just the prefix part
            if let Some(prefix_bytes) = ckey.first() {
                let pre = String::from_utf8_lossy(prefix_bytes).to_string();
                let fn_num = cn;
                let dig = String::from_utf8_lossy(&cval).to_string();

                items.push((pre, fn_num, dig));
            }
        }

        // Sort by first seen order number to ensure proper ordering
        items.sort_by(|a, b| a.1.cmp(&b.1));

        Ok(items)
    }

    /// Returns iterator of first seen event messages with attachments for all
    /// identifier prefixes starting at the beginning of the database.
    /// Essentially a replay in first seen order with attachments of entire
    /// set of FELs (First Seen Event Logs).
    ///
    /// # Returns
    /// * `Result<Vec<Vec<u8>>, DBError>` - Collection of all event messages with attachments
    pub fn clone_all_pre_iter(&self) -> Result<Vec<Vec<u8>>, DBError> {
        let mut msgs = Vec::new();

        // Get all (pre, fn, dig) triples from the FEL database
        let fel_items = self.get_fel_item_all_pre_iter()?;

        // For each item, try to clone the event message
        for (pre, fn_num, dig) in fel_items {
            match self.clone_evt_msg(&pre, fn_num, &dig) {
                Ok(msg) => msgs.push(msg),
                Err(_) => continue, // Skip this event if there's an error, as in Python implementation
            }
        }

        Ok(msgs)
    }
    /// Return count of signatures at key.
    /// Uses dgKey format for the key.
    /// Returns zero if no entry at key.
    ///
    /// # Parameters
    /// * `key` - The key to count signatures for (should be in dgKey format)
    ///
    /// # Returns
    /// * `Result<usize, DBError>` - Count of signatures, zero if no entry
    pub fn cnt_sigs(&self, key: &[u8]) -> Result<usize, DBError> {
        self.sigs
            .cnt(&[key])
            .map_err(|e| DBError::DatabaseError(format!("Error counting signatures: {}", e)))
    }
    pub fn get_sigs_iter(
        &self,
        key: &[u8],
    ) -> Result<impl Iterator<Item = Result<Vec<u8>, DBError>>, DBError> {
        let iter = self.sigs.get_iter::<_, Vec<u8>>(&[key]).map_err(|e| {
            DBError::DatabaseError(format!("Error getting signatures iterator: {}", e))
        })?;

        // Collect into a Vec to avoid lifetime issues with the mapped iterator
        let results: Vec<Result<Vec<u8>, DBError>> = iter
            .map(|result| {
                result.map_err(|e| {
                    DBError::DatabaseError(format!("Error deserializing signature: {}", e))
                })
            })
            .collect();

        Ok(results.into_iter())
    }

    /// Fetch transferable signature groups from the ssgs database
    ///
    /// # Parameters
    /// * `saider` - SAID for the reply to which signatures are attached
    /// * `snh` - Optional sequence number hex string for filtering
    ///
    /// # Returns
    /// * `Ok(Vec<(Prefixer, Seqner, Diger, Vec<Siger>)>)` - List of signature groups
    /// * `Err(KERIError)` - On database error or parsing failure
    pub fn fetch_tsgs(
        &self,
        saider: Saider,
        snh: Option<&str>,
    ) -> Result<Vec<(Prefixer, Seqner, Diger, Vec<Siger>)>, KERIError> {
        let mut tsgs = Vec::new();
        let mut sigers = Vec::new();
        let mut old: Option<Vec<Vec<u8>>> = None;

        // Get items from ssgs database
        let items = self
            .ssgs
            .get_item_iter(&[saider.qb64().as_bytes(), b""], false)
            .map_err(|e| {
                KERIError::DatabaseError(format!("Failed to get signature items: {}", e))
            })?;

        for (keys, siger_matters) in items {
            if keys.len() < 2 {
                continue;
            }

            let triple = keys[1..].to_vec(); // Skip the saider key, take the triple

            if Some(&triple) != old.as_ref() {
                // New signature group
                if let Some(snh) = snh {
                    if triple.len() >= 2 {
                        let seq_str = String::from_utf8_lossy(&triple[1]);
                        if seq_str.as_ref() > snh {
                            // Use .as_ref() to convert Cow to &str
                            break; // Only process lower sequence numbers
                        }
                    }
                }

                if !sigers.is_empty() && old.is_some() {
                    // Append the previous signature group
                    if let Some(old_triple) = &old {
                        let (prefixer, seqner, diger) = self.klasify_triple(old_triple)?;
                        tsgs.push((prefixer, seqner, diger, sigers.clone()));
                        sigers.clear();
                    }
                }
                old = Some(triple);
            }

            // Convert Matter instances to Siger
            for siger_matter in siger_matters {
                if let Some(siger) = siger_matter.as_any().downcast_ref::<Siger>() {
                    sigers.push(siger.clone());
                }
            }
        }

        // Handle the last group
        if !sigers.is_empty() && old.is_some() {
            if let Some(old_triple) = &old {
                let (prefixer, seqner, diger) = self.klasify_triple(old_triple)?;
                tsgs.push((prefixer, seqner, diger, sigers));
            }
        }

        Ok(tsgs)
    }

    /// Convert a triple of serialized values to Prefixer, Seqner, Diger instances
    /// Rust implementation of the klasify function for the specific case of (Prefixer, Seqner, Diger)
    ///
    /// # Parameters
    /// * `triple` - Vector of byte vectors representing [prefixer, seqner, diger]
    ///
    /// # Returns
    /// * `Ok((Prefixer, Seqner, Diger))` - Converted instances
    /// * `Err(KERIError)` - On conversion failure
    fn klasify_triple(&self, triple: &[Vec<u8>]) -> Result<(Prefixer, Seqner, Diger), KERIError> {
        if triple.len() != 3 {
            return Err(KERIError::ValidationError(
                "Expected triple of values".to_string(),
            ));
        }

        let prefixer = Prefixer::from_qb64(&String::from_utf8_lossy(&triple[0]))
            .map_err(|e| KERIError::ValidationError(format!("Failed to create Prefixer: {}", e)))?;

        let seqner = Seqner::from_snh(&String::from_utf8_lossy(&triple[1]))
            .map_err(|e| KERIError::ValidationError(format!("Failed to create Seqner: {}", e)))?;

        let diger = Diger::from_qb64(&String::from_utf8_lossy(&triple[2]))
            .map_err(|e| KERIError::ValidationError(format!("Failed to create Diger: {}", e)))?;

        Ok((prefixer, seqner, diger))
    }
}

impl<'db> Drop for Baser<'db> {
    fn drop(&mut self) {
        // This is a no-op, as the LMDBer will be dropped automatically
        // and it has its own Drop implementation
    }
}
