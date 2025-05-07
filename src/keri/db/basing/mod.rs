mod key_state_record;

use crate::cesr::number::Number;
use crate::keri::core::filing::{BaseFiler, Filer, FilerDefaults};
use crate::keri::db::dbing::LMDBer;
use crate::keri::db::errors::DBError;
use crate::keri::db::koming::{Komer, SerialKind};
use crate::keri::db::subing::cesr::CesrSuber;
use crate::keri::db::subing::dup::DupSuber;
use crate::keri::db::subing::iodup::IoDupSuber;
use crate::keri::db::subing::on::OnSuber;
use crate::keri::db::subing::oniodup::OnIoDupSuber;
use crate::keri::db::subing::{Suber, Utf8Codec};
use indexmap::IndexSet;
pub use key_state_record::KeyStateRecord;
pub use key_state_record::StateEERecord;
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

/// Baser struct for key event log and escrow storage (DB)
/// Sets up named sub databases for key event logs and escrow storage.
pub struct Baser<'db> {
    /// Base database
    lmdber: Arc<&'db LMDBer>, // The base LMDB database

    pub prefixes: IndexSet<String>,
    pub groups: IndexSet<String>,

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
    pub aess: DupSuber<'db>,

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

    /// Prefix situation database
    /// Key is identifier prefix (fully qualified qb64)
    /// Value is serialized parameter dict of public key situation
    pub states: Komer<'db, KeyStateRecord>,
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

            // Initialize the aess sub database
            aess: DupSuber::new(lmdber.clone(), "aess.", None, false)
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

            // Initialize the states sub database
            states: Komer::new(lmdber.clone(), "stts.", SerialKind::Json)
                .map_err(|e| DBError::DatabaseError(format!("SuberError: {}", e)))?,
        };

        Ok(baser)
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

impl<'db> Drop for Baser<'db> {
    fn drop(&mut self) {
        // This is a no-op, as the LMDBer will be dropped automatically
        // and it has its own Drop implementation
    }
}
