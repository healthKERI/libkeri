mod key_state_record;

use crate::cesr::counting::{ctr_dex_1_0, BaseCounter, Counter};
use crate::cesr::dater::Dater;
use crate::cesr::num_dex;
use crate::cesr::number::Number;
use crate::keri::core::eventing::Kever;
use crate::keri::core::filing::{BaseFiler, Filer, FilerDefaults};
use crate::keri::core::serdering::{Serder, SerderKERI};
use crate::keri::db::dbing::keys::dg_key;
use crate::keri::db::dbing::LMDBer;
use crate::keri::db::errors::DBError;
use crate::keri::db::koming::{Komer, SerialKind};
use crate::keri::db::subing::cesr::CesrSuber;
use crate::keri::db::subing::dup::DupSuber;
use crate::keri::db::subing::iodup::IoDupSuber;
use crate::keri::db::subing::on::OnSuber;
use crate::keri::db::subing::oniodup::OnIoDupSuber;
use crate::keri::db::subing::{Suber, Utf8Codec};
use crate::Matter;
use chrono::DateTime;
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

/// Baser struct for key event log and escrow storage (DB)
/// Sets up named sub databases for key event logs and escrow storage.
pub struct Baser<'db> {
    /// Base database
    lmdber: Arc<&'db LMDBer>, // The base LMDB database

    pub prefixes: IndexSet<String>,
    pub groups: IndexSet<String>,
    pub kevers: HashMap<String, Kever<'db>>,

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
}

impl<'db> Drop for Baser<'db> {
    fn drop(&mut self) {
        // This is a no-op, as the LMDBer will be dropped automatically
        // and it has its own Drop implementation
    }
}
