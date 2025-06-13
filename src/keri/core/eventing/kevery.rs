use crate::cesr::cigar::Cigar;
use crate::cesr::dater::Dater;
use crate::cesr::indexing::siger::Siger;
use crate::cesr::indexing::Indexer;
use crate::cesr::prefixer::Prefixer;
use crate::cesr::saider::Saider;
use crate::cesr::seqner::Seqner;
use crate::cesr::verfer::Verfer;
use crate::keri::core::eventing::kever::Kever;
use crate::keri::core::eventing::{verify_sigs, ReplyEventBuilder};
use crate::keri::core::parsing::Trqs;
use crate::keri::core::serdering::{Rawifiable, SadValue, Serder, SerderKERI};
use crate::keri::db::basing::Baser;
use crate::keri::db::dbing::keys::{dg_key, sn_key};
use crate::keri::{Ilk, KERIError};
use crate::Matter;
use indexmap::IndexSet;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use tracing::{debug, info};

/// Kevery (Key Event Message Processing Facility) processes an incoming
/// message stream composed of KERI key event related messages and attachments.
/// Kevery acts a Kever (key event verifier) factory for managing key state of
/// KERI identifier prefixes.
///
/// Only supports current version VERSION
pub struct Kevery<'db> {
    /// Database instance for KERI event storage
    pub db: Arc<&'db Baser<'db>>,

    /// Notices of events needing receipt or requests needing response
    pub cues: VecDeque<Cue>,

    /// Optional recovery module
    pub rvy: Option<Rvy<'db>>,

    /// True means operate in promiscuous (unrestricted) mode,
    /// False means operate in nonpromiscuous (restricted) mode
    /// as determined by local and prefixes
    pub lax: bool,

    /// True means event source is local (protected) for validation
    /// False means event source is remote (unprotected) for validation
    pub local: bool,

    /// True means cloned message stream so use attached datetimes from clone source not own
    /// False means use current datetime
    pub cloned: bool,

    /// True means direct mode so cue notices for receipts etc
    /// False means indirect mode so don't cue notices
    pub direct: bool,

    /// True means do not update the database in any non-idempotent way.
    /// Useful for reinitializing the Kevers from a persisted KEL without
    /// updating non-idempotent first seen .fels and timestamps.
    pub check: bool,

    /// Cache of kevers indexed by prefix
    kevers: HashMap<String, Kever<'db>>,
}

/// Cue represents a notice of an event needing receipt or a request needing response
#[derive(Debug, Clone)]
pub struct Cue {
    kin: String,
    serder: SerderKERI,
}

/// Recovery module for Kevery
pub struct Rvy<'db> {
    pub db: Baser<'db>,
}

impl<'db> Kevery<'db> {
    /// Timeout constants (in seconds)
    pub const TIMEOUT_OOE: u64 = 1200; // seconds to timeout out of order escrows
    pub const TIMEOUT_PSE: u64 = 3600; // seconds to timeout partially signed or delegated escrows
    pub const TIMEOUT_PWE: u64 = 3600; // seconds to timeout partially witnessed escrows
    pub const TIMEOUT_LDE: u64 = 3600; // seconds to timeout likely duplicitous escrows
    pub const TIMEOUT_UWE: u64 = 3600; // seconds to timeout unverified receipt escrows
    pub const TIMEOUT_URE: u64 = 3600; // seconds to timeout unverified receipt escrows
    pub const TIMEOUT_VRE: u64 = 3600; // seconds to timeout unverified transferable receipt escrows
    pub const TIMEOUT_KSN: u64 = 3600; // seconds to timeout key state notice message escrows
    pub const TIMEOUT_QNF: u64 = 300; // seconds to timeout query not found escrows

    /// Initialize a new Kevery instance
    ///
    /// # Parameters
    /// * `cues` - Optional cues to initialize with
    /// * `db` - Database instance
    /// * `rvy` - Optional recovery module
    /// * `lax` - True means operate in promiscuous (unrestricted) mode
    /// * `local` - True means event source is local (protected) for validation
    /// * `cloned` - True means cloned message stream so use attached datetimes from clone source
    /// * `direct` - True means direct mode so cue notices for receipts etc
    /// * `check` - True means do not update the database in any non-idempotent way
    pub fn new(
        cues: Option<VecDeque<Cue>>,
        db: Arc<&'db Baser<'db>>,
        rvy: Option<Rvy<'db>>,
        lax: Option<bool>,
        local: Option<bool>,
        cloned: Option<bool>,
        direct: Option<bool>,
        check: Option<bool>,
    ) -> Result<Self, KERIError> {
        let db = db;

        Ok(Self {
            cues: cues.unwrap_or_else(VecDeque::new),
            db,
            rvy,
            lax: lax.unwrap_or(true),
            local: local.unwrap_or(false),
            cloned: cloned.unwrap_or(false),
            direct: direct.unwrap_or(true),
            check: check.unwrap_or(false),
            kevers: HashMap::new(),
        })
    }

    /// Get a reference to the kevers dictionary
    pub fn kevers(&self) -> &HashMap<String, Kever<'db>> {
        &self.kevers
    }

    /// Get the prefixes as an ordered set
    pub fn prefixes(&self) -> &IndexSet<String> {
        &self.db.prefixes
    }

    /// Process one event serder with attached indexed signatures sigers
    ///
    /// # Parameters
    /// * `serder` - Instance of event to process
    /// * `sigers` - Instances of attached controller indexed sigs
    /// * `wigers` - Instances of attached witness indexed sigs, otherwise None
    /// * `delseqner` - Instance of delegating event sequence number.
    ///                If this event is not delegated then seqner is ignored
    /// * `delsaider` - Instance of delegating event SAID.
    ///                If this event is not delegated then saider is ignored
    /// * `firner` - Instance of cloned first seen ordinal.
    ///             If cloned mode then firner maybe provided (not None)
    /// * `dater` - Instance of cloned replay datetime.
    ///            If cloned mode then dater maybe provided (not None)
    /// * `eager` - True means try harder to find validate events by walking KELs.
    ///            False means only use pre-existing information if any.
    /// * `local` - True means local (protected) event source.
    ///            False means remote (unprotected).
    ///            None means use default .local.
    pub fn process_event(
        &mut self,
        serder: SerderKERI,
        sigers: Vec<Siger>,
        wigers: Option<Vec<Siger>>,
        delseqner: Option<Seqner>,
        delsaider: Option<Saider>,
        firner: Option<Seqner>,
        dater: Option<Dater>,
        eager: Option<bool>,
        local: Option<bool>,
    ) -> Result<(), KERIError> {
        let eager = eager.unwrap_or(false);
        // Use provided local or default to self.local, and force it to be a boolean
        let local = match local {
            Some(val) => val,
            None => self.local,
        };

        // Fetch ked ilk, pre, sn, dig to see how to process
        let pre = serder
            .pre()
            .ok_or_else(|| KERIError::ValueError("Missing pre in event".to_string()))?;
        let ked = serder.ked();

        // See if code of pre is supported and matches size of pre
        match Prefixer::from_qb64(&pre) {
            Ok(_) => (),
            Err(e) => {
                return Err(KERIError::ValueError(format!(
                    "Invalid pre = {:?} for evt = {:?}. Error: {:?}",
                    &pre, &ked, e
                ))
                .into());
            }
        }

        let sn = serder
            .sn()
            .ok_or_else(|| KERIError::ValueError("Missing sn in event".to_string()))?;
        let ilk = serder
            .ilk()
            .ok_or_else(|| KERIError::ValueError("Missing ilk in event".to_string()))?;
        let said = serder
            .said()
            .ok_or_else(|| KERIError::ValueError("Missing said in event".to_string()))?;

        if !self.kevers.contains_key(&pre) {
            // First seen event for pre
            if ilk == Ilk::Icp || ilk == Ilk::Dip {
                // First seen and inception so verify event keys

                // Create kever from serder
                let kever = Kever::new(
                    Arc::new(&self.db),
                    None, // state
                    Some(serder.clone()),
                    Some(sigers.clone()),
                    wigers.clone(),
                    None, // est_only
                    delseqner,
                    delsaider,
                    if self.cloned { firner } else { None },
                    if self.cloned { dater } else { None },
                    Some(eager),
                    Some(local),
                    Some(self.check),
                )?;

                // Not exception so add to kevers
                self.kevers.insert(pre.clone(), kever);

                // At this point the inceptive event (icp or dip) given by serder
                // together with its attachments has been accepted as valid with finality.
                // Events that don't get to here have either been dropped as
                // invalid by raising an error or have been escrowed as not
                // yet complete enough to decide their validity.

                // Handle cues for receipt or notice
                if self.direct || self.lax || !self.db.prefixes.contains(&pre) {
                    // Create cue for receipt controller or watcher
                    self.cues.push_back(Cue {
                        kin: "receipt".to_string(),
                        serder: serder.clone(),
                    });
                } else if !self.direct {
                    // Notice of new event
                    self.cues.push_back(Cue {
                        kin: "notice".to_string(),
                        serder: serder.clone(),
                    });
                }

                // Handle witness cues if needed
                if self.local && self.kevers[&pre].locally_witnessed(None, Some(&serder)) {
                    // TODO: need to cue task here kin = "witness" and process
                    // cued witness and then combine with receipt above so only
                    // one receipt is generated not two
                    self.cues.push_back(Cue {
                        kin: "witness".to_string(),
                        serder: serder.clone(),
                    });
                }
            } else {
                // Not inception so can't verify sigs etc, add to out-of-order escrow
                self.escrow_oo_event(
                    &serder,
                    &sigers,
                    delseqner.as_ref(),
                    delsaider.as_ref(),
                    Some(&wigers.unwrap_or_default()),
                    local,
                )?;

                return Err(
                    KERIError::OutOfOrderError(format!("Out-of-order event={:?}.", ked)).into(),
                );
            }
        } else {
            // Already accepted inception event for pre so already first seen
            if ilk == Ilk::Icp || ilk == Ilk::Dip {
                // Another inception event so maybe duplicitous
                if sn != 0 {
                    return Err(KERIError::ValueError(format!(
                        "Invalid sn={} for inception event={:?}.",
                        sn,
                        serder.ked()
                    ))
                    .into());
                }

                // Check if duplicate of existing inception event since est is icp
                let eserder = match self.fetch_est_event(&pre, sn) {
                    Some(serder) => serder,
                    None => {
                        return Err(KERIError::ValueError(
                            "Kever not found for known prefix".to_string(),
                        ));
                    }
                };
                if eserder.said().unwrap_or_default() == said {
                    // Event is a duplicate but not duplicitous
                    // May have attached valid signature not yet logged
                    let kever = self.kevers.get(&pre).ok_or_else(|| {
                        KERIError::ValueError("Kever not found for known prefix".to_string())
                    })?;

                    // Get unique verified lists of sigers and indices from sigers
                    let (verified_sigers, _) = verify_sigs(
                        &serder.raw(),
                        sigers,
                        &eserder.verfers().unwrap_or_default(),
                    )?;

                    let berfers = eserder.berfers().unwrap_or_default();
                    let (verified_wigers, _) = if let Some(w) = wigers {
                        verify_sigs(&serder.raw(), w, &berfers)?
                    } else {
                        (vec![], vec![])
                    };

                    if !verified_sigers.is_empty() || !verified_wigers.is_empty() {
                        // At least one verified sig or wig so log evt
                        // This allows late arriving witness receipts or controller
                        // signatures to be added to the database
                        kever.log_event(
                            serder.clone(),
                            verified_sigers,
                            if verified_wigers.is_empty() {
                                None
                            } else {
                                Some(verified_wigers)
                            },
                            None,  // wits
                            false, // not first seen
                            None,  // seqner
                            None,  // saider
                            None,  // firner
                            None,  // dater
                            local,
                        )?;
                    }
                } else {
                    // Escrow likely duplicitous event
                    self.escrow_ld_event(&serder, &sigers)?;

                    let msg = format!(
                        "Likely Duplicitous Event sn={} type={:?} SAID={}",
                        serder.sn().unwrap_or_default(),
                        serder.ilk(),
                        serder.said().unwrap_or_default()
                    );
                    debug!("{}", msg);
                    debug!("Duplicitous event body=\n{}\n", serder.pretty(None));

                    return Err(KERIError::LikelyDuplicitousError(msg).into());
                }
            } else {
                // rot, drt, or ixn, so sn matters
                let kever = self.kevers.get(&pre).ok_or_else(|| {
                    KERIError::ValueError("Kever not found for known prefix".to_string())
                })?;

                let sno = kever.sner().map(|s| s.num()).unwrap_or_default() + 1; // proper sn of new inorder event

                if sn > sno as u64 {
                    // sn later than sno so out of order escrow
                    self.escrow_oo_event(
                        &serder,
                        &sigers,
                        delseqner.as_ref(),
                        delsaider.as_ref(),
                        Some(&wigers.unwrap_or_default()),
                        local,
                    )?;

                    let msg = format!(
                        "Out-of-order event sn={} type={:?} SAID={}",
                        serder.sn().unwrap_or_default(),
                        serder.ilk(),
                        serder.said().unwrap_or_default()
                    );
                    debug!("{}", msg);
                    debug!("Out-of-order event body=\n{}\n", serder.pretty(None));

                    return Err(KERIError::OutOfOrderError(msg).into());
                } else if (sn == sno as u64) || // inorder event (ixn, rot, drt) or
                    (ilk == Ilk::Rot && // superseding recovery rot or
                        kever.last_est().map(|l| l.s < sn && sn <= sno as u64).unwrap_or(false)) ||
                    (ilk == Ilk::Drt && // delegated superseding recovery drt
                        kever.last_est().map(|l| l.s <= sn && sn <= sno as u64).unwrap_or(false))
                {
                    // Verify signatures etc and update state if valid
                    let kever = self.kevers.get_mut(&pre).ok_or_else(|| {
                        KERIError::ValueError("Kever not found for known prefix".to_string())
                    })?;

                    kever.update(
                        serder.clone(),
                        sigers.clone(),
                        wigers.clone(),
                        delseqner,
                        delsaider,
                        if self.cloned { firner } else { None },
                        if self.cloned { dater } else { None },
                        eager,
                        local,
                        self.check,
                    )?;

                    // At this point the non-inceptive event (rot, drt, or ixn)
                    // given by serder together with its attachments has been
                    // accepted as valid with finality.

                    // Handle cues for receipt or notice
                    if self.direct || self.lax || !self.db.prefixes.contains(&pre) {
                        // Create cue for receipt controller or watcher
                        self.cues.push_back(Cue {
                            kin: "receipt".to_string(),
                            serder: serder.clone(),
                        });
                    } else if !self.direct {
                        // Notice of new event
                        self.cues.push_back(Cue {
                            kin: "notice".to_string(),
                            serder: serder.clone(),
                        });
                    }

                    // Handle witness cues if needed
                    if self.local && kever.locally_witnessed(None, Some(&serder)) {
                        // TODO: need to cue task here kin = "witness" and process
                        // cued witness and then combine with receipt above so only
                        // one receipt is generated not two
                        self.cues.push_back(Cue {
                            kin: "witness".to_string(),
                            serder: serder.clone(),
                        });
                    }
                } else {
                    // Maybe duplicitous
                    // Check if duplicate of existing valid accepted event
                    let key = sn_key(&pre, sn);
                    let ddig_res = self.db.kels.get_last::<_, Vec<u8>>(&[&key])?;

                    if let Some(ddig) = ddig_res {
                        let ddig_str = String::from_utf8(ddig).map_err(|_| {
                            KERIError::ValueError("Invalid UTF-8 in digest".to_string())
                        })?;

                        if ddig_str == said {
                            // Event is a duplicate but not duplicitous
                            let eserder = self.fetch_est_event(&pre, sn).unwrap();

                            // May have attached valid signature not yet logged
                            let kever = self.kevers.get(&pre).ok_or_else(|| {
                                KERIError::ValueError(
                                    "Kever not found for known prefix".to_string(),
                                )
                            })?;

                            // Get unique verified lists of sigers and indices from sigers
                            let (verified_sigers, _) = verify_sigs(
                                &serder.raw(),
                                sigers,
                                &eserder.verfers().unwrap_or_default(),
                            )?;

                            let wits = self.fetch_witness_state(&pre, sn)?;
                            let werfers: Vec<Verfer> = wits
                                .iter()
                                .map(|wit| Verfer::from_qb64(wit))
                                .collect::<Result<Vec<Verfer>, _>>()?;

                            let (verified_wigers, _) = if let Some(w) = wigers {
                                verify_sigs(&serder.raw(), w, &werfers)?
                            } else {
                                (vec![], vec![])
                            };

                            if !verified_sigers.is_empty() || !verified_wigers.is_empty() {
                                // At least one verified sig or wig so log evt
                                kever.log_event(
                                    serder.clone(),
                                    verified_sigers,
                                    if verified_wigers.is_empty() {
                                        None
                                    } else {
                                        Some(verified_wigers)
                                    },
                                    None,  // wits
                                    false, // not first seen
                                    None,  // seqner
                                    None,  // saider
                                    None,  // firner
                                    None,  // dater
                                    local,
                                )?;
                            }
                        } else {
                            // Escrow likely duplicitous event
                            self.escrow_ld_event(&serder, &sigers)?;

                            let msg = format!(
                                "Likely Duplicitous Event sn={} type={:?} SAID={}",
                                serder.sn().unwrap_or_default(),
                                serder.ilk(),
                                serder.said().unwrap_or_default()
                            );
                            debug!("{}", msg);
                            debug!("Duplicitous event body=\n{}\n", serder.pretty(None));

                            return Err(KERIError::LikelyDuplicitousError(msg).into());
                        }
                    } else {
                        // No existing event found, escrow as likely duplicitous
                        self.escrow_ld_event(&serder, &sigers)?;

                        let msg = format!(
                            "Likely Duplicitous Event (no existing event) sn={} type={:?} SAID={}",
                            serder.sn().unwrap_or_default(),
                            serder.ilk(),
                            serder.said().unwrap_or_default()
                        );
                        debug!("{}", msg);

                        return Err(KERIError::LikelyDuplicitousError(msg).into());
                    }
                }
            }
        }

        Ok(())
    }

    // These methods would be implemented as helper functions

    /// Fetch the latest establishment event for a prefix at a sequence number
    fn fetch_est_event(&self, pre: &str, sn: u64) -> Option<SerderKERI> {
        let mut sn = sn;
        loop {
            let key = sn_key(&pre, sn);
            match self.db.kels.get_last::<_, Vec<u8>>(&[&key]) {
                Ok(dig_bytes) => {
                    let ldig = match dig_bytes {
                        Some(dig_bytes) => match String::from_utf8(dig_bytes) {
                            Ok(ldig) => ldig,
                            Err(_) => return None,
                        },
                        None => return None,
                    };

                    let dgkey = dg_key(pre, ldig);
                    let raw = match self.db.evts.get::<_, Vec<u8>>(&[&dgkey]) {
                        Ok(r) => r.unwrap(),
                        Err(_) => return None,
                    };

                    let serder = SerderKERI::from_raw(&raw, None).unwrap();
                    let ilk = serder.ilk();
                    if ilk == Some(Ilk::Icp)
                        || ilk == Some(Ilk::Dip)
                        || ilk == Some(Ilk::Rot)
                        || ilk == Some(Ilk::Drt)
                    {
                        return Some(serder);
                    }

                    sn = serder.sn().unwrap() - 1;
                }
                Err(_) => return None,
            }
        }
    }

    /// Fetch the witness state for a prefix at a sequence number
    fn fetch_witness_state(&self, _pre: &str, _sn: u64) -> Result<Vec<String>, KERIError> {
        // Implementation details would go here
        todo!("Implement fetch_witness_state method")
    }

    /// Escrow an out-of-order event
    fn escrow_oo_event(
        &self,
        _serder: &SerderKERI,
        _sigers: &[Siger],
        _seqner: Option<&Seqner>,
        _saider: Option<&Saider>,
        _wigers: Option<&[Siger]>,
        _local: bool,
    ) -> Result<(), KERIError> {
        // Implementation details would go here
        todo!("Implement escrow_oo_event method")
    }

    /// Escrow a likely duplicitous event
    fn escrow_ld_event(&self, _serder: &SerderKERI, _sigers: &[Siger]) -> Result<(), KERIError> {
        // Implementation details would go here
        todo!("Implement escrow_ld_event method")
    }

    /// Process one witness receipt serder with attached witness wigers (indexed signatures)
    ///
    /// # Parameters
    /// * `serder` - Instance of serialized receipt message (not receipted event)
    /// * `wigers` - Instances that with witness indexed signatures. Index is offset into
    ///             witness list of latest establishment event for receipted event.
    ///             Signature uses key pair derived from nontrans witness prefix in
    ///             associated witness list.
    /// * `local` - True means local (protected) event source.
    ///            False means remote (unprotected).
    ///            None means use default .local.
    ///
    /// Receipt dict labels
    /// * vs  - version string
    /// * pre - qb64 prefix
    /// * sn  - hex string sequence number
    /// * ilk - rct
    /// * dig - qb64 digest of receipted event
    pub fn process_receipt_witness(
        &self,
        serder: SerderKERI,
        wigers: Vec<Siger>,
        local: Option<bool>,
    ) -> Result<(), KERIError> {
        // Use provided local or default to self.local, and force it to be a boolean
        let local = match local {
            Some(val) => val,
            None => self.local,
        };

        // Fetch pre, dig to process
        let ked = serder.ked();
        let pre = serder
            .pre()
            .ok_or_else(|| KERIError::ValueError("Missing pre in receipt".to_string()))?;
        let sn = serder
            .sn()
            .ok_or_else(|| KERIError::ValueError("Missing sn in receipt".to_string()))?;

        // Only accept receipt if for last seen version of event at sn
        let sn_key = sn_key(&pre, sn);

        // Retrieve dig of last event at sn
        let ldig = match self.db.kels.get_last::<_, Vec<u8>>(&[&sn_key])? {
            Some(dig_bytes) => String::from_utf8(dig_bytes)
                .map_err(|_| KERIError::ValueError("Invalid UTF-8 in digest".to_string()))?,
            None => {
                // No events to be receipted yet at that sn, so escrow
                // Get digest from receipt message not receipted event
                let receipt_dig = ked
                    .get("d")
                    .ok_or_else(|| {
                        KERIError::ValueError("Missing 'd' field in receipt".to_string())
                    })?
                    .as_str()
                    .ok_or_else(|| {
                        KERIError::ValueError("'d' field is not a string".to_string())
                    })?;

                self.escrow_uw_receipt(&serder, &wigers, receipt_dig)?;

                let msg = format!(
                    "Unverified witness receipt={}",
                    serder.said().unwrap_or_default()
                );
                info!("{}", msg);
                debug!("Event=\n{}\n", serder.pretty(None));

                return Err(KERIError::UnverifiedWitnessReceiptError(msg).into());
            }
        };

        // Verify digs match
        if !serder.compare_said(
            ked.get("d")
                .ok_or_else(|| KERIError::ValueError("Missing 'd' field in receipt".to_string()))?
                .as_str()
                .ok_or_else(|| KERIError::ValueError("'d' field is not a string".to_string()))?,
        ) {
            // Stale receipt at sn, discard
            let msg = format!(
                "Stale receipt at sn = {:?} for rct = {:?}",
                ked.get("s").unwrap(),
                serder.said().unwrap_or_default()
            );
            info!("{}", msg);
            debug!("Stale receipt event body=\n{}\n", serder.pretty(None));

            return Err(KERIError::ValueError(msg).into());
        }

        // Retrieve receipted event at dig
        let dg_key = dg_key(&pre, &ldig);
        let raw =
            self.db.evts.get::<_, Vec<u8>>(&[&dg_key])?.ok_or_else(|| {
                KERIError::ValueError(format!("Event not found for dig={}", ldig))
            })?;

        let lserder = SerderKERI::from_raw(&raw, None)?;

        // Process each couple, verify sig and write to db
        let wits = self.fetch_witness_state(&pre, sn)?;

        for wiger in wigers {
            // Assign verfers from witness list
            if wiger.index() >= wits.len() as u32 {
                continue; // Skip invalid witness index
            }

            let wiger_verfer = Verfer::from_qb64(&wits[wiger.index() as usize])?;

            // Skip transferable verfers
            if wiger_verfer.is_transferable() {
                continue; // Skip invalid witness prefix
            }

            // Handle own witness scenarios
            if !self.lax && self.db.prefixes.contains(&wiger_verfer.qb64()) {
                // Own is witness
                if self.db.prefixes.contains(&pre) {
                    // Skip own receiptor of own event - sign own events not receipt them
                    info!(
                        "Kevery: skipped own receipt attachment on own event receipt={}",
                        serder.said().unwrap_or_default()
                    );
                    debug!("Event=\n{}\n", serder.pretty(None));
                    continue;
                }

                if !local {
                    // Skip own receipt on other event when non-local source
                    debug!(
                        "Kevery: skipped own receipt attachment on nonlocal event receipt={}",
                        serder.said().unwrap_or_default()
                    );
                    debug!("Event=\n{}\n", serder.pretty(None));
                    continue;
                }
            }

            // Verify signature
            if wiger_verfer.verify(&wiger.raw(), &lserder.raw())? {
                // Write receipt indexed sig to database
                self.db.wigs.add(&[&dg_key], &wiger.qb64().as_bytes())?;
            }
        }

        Ok(())
    }

    pub fn process_attached_receipt_couples(
        &mut self,
        _serder: SerderKERI,
        _firner: Option<Seqner>,
        _cigars: Vec<Cigar>,
    ) -> Result<(), KERIError> {
        // todo!("Implement process_attached_receipt_couples method")
        Ok(())
    }

    pub fn process_attached_receipt_quadruples(
        &mut self,
        _serder: SerderKERI,
        _trqs: Vec<Trqs>,
        _firner: Option<Seqner>,
        _local: Option<bool>,
    ) -> Result<(), KERIError> {
        // todo!("Implement process_attached_receipt_quadruples method")
        Ok(())
    }

    /// Process one receipt serder with attached cigars
    /// may or may not be a witness receipt. If prefix matches witness then
    /// promote to indexed witness signature and store appropriately. Otherwise
    /// signature is nontrans nonwitness endorser (watcher etc)
    ///
    /// # Parameters
    /// * `serder` - Receipt instance of serialized receipt message
    /// * `cigars` - Instances that contain receipt couple signature in .raw and public key in .verfer
    /// * `local` - True means local (protected) event source.
    ///            False means remote (unprotected).
    ///            None means use default .local.
    ///
    /// Receipt dict labels
    /// * vs  - version string
    /// * pre - qb64 prefix
    /// * sn  - hex string sequence number
    /// * ilk - rct
    /// * dig - qb64 digest of receipted event
    pub fn process_receipt(
        &mut self,
        serder: SerderKERI,
        cigars: Vec<Cigar>,
        local: Option<bool>,
    ) -> Result<(), KERIError> {
        // Use provided local or default to self.local, and force it to be a boolean
        let local = match local {
            Some(val) => val,
            None => self.local,
        };

        // Fetch pre, dig to process
        let ked = serder.ked();
        let pre = serder
            .pre()
            .ok_or_else(|| KERIError::ValueError("Missing pre in receipt".to_string()))?;
        let sn = serder
            .sn()
            .ok_or_else(|| KERIError::ValueError("Missing sn in receipt".to_string()))?;

        // Only accept receipt if for last seen version of event at sn
        let sn_key = sn_key(&pre, sn);

        // Retrieve dig of last event at sn
        let dig_bytes = self.db.kels.get_on::<_, Vec<u8>>(&[&sn_key], 0)?;
        let ldig = if dig_bytes.is_empty() {
            String::from_utf8(dig_bytes.get(0).unwrap().to_vec())
                .map_err(|_| KERIError::ValueError("Invalid UTF-8 in digest".to_string()))?
        } else {
            // No events to be receipted yet at that sn, so escrow
            // Get digest from receipt message not receipted event
            let receipt_dig = ked
                .get("d")
                .ok_or_else(|| KERIError::ValueError("Missing 'd' field in receipt".to_string()))?
                .as_str()
                .ok_or_else(|| KERIError::ValueError("'d' field is not a string".to_string()))?;

            self.escrow_u_receipt(&serder, &cigars, receipt_dig)?;

            let msg = format!("Unverified receipt = {}", serder.said().unwrap_or_default());
            info!("{}", msg);
            debug!("Event=\n{}\n", serder.pretty(None));

            return Err(KERIError::UnverifiedReceiptError(msg).into());
        };

        // Verify digs match
        if !serder.compare_said(
            ked.get("d")
                .ok_or_else(|| KERIError::ValueError("Missing 'd' field in receipt".to_string()))?
                .as_str()
                .ok_or_else(|| KERIError::ValueError("'d' field is not a string".to_string()))?,
        ) {
            // Stale receipt at sn, discard
            let msg = format!(
                "Stale receipt at sn = {:?} for rct = {:?}",
                ked.get("s").unwrap_or(&SadValue::String("".to_string())),
                serder.said().unwrap_or_default()
            );

            return Err(KERIError::ValueError(msg).into());
        }

        // Retrieve receipted event at dig
        let dg_key = dg_key(&pre, ldig.clone());
        let raw =
            self.db.evts.get::<_, Vec<u8>>(&[&dg_key])?.ok_or_else(|| {
                KERIError::ValueError(format!("Event not found for dig={:?}", ldig))
            })?;

        let lserder = SerderKERI::from_raw(&raw, None)?;

        // Process each cigar, verify sig and write to db
        for cigar in cigars {
            // Skip transferable verfers
            if cigar.verfer.clone().unwrap().is_transferable() {
                continue;
            }

            // Handle own receiptor scenarios
            if !self.lax
                && self
                    .db
                    .prefixes
                    .contains(&cigar.verfer.clone().unwrap().qb64())
            {
                // Own is receiptor
                if self.db.prefixes.contains(&pre) {
                    // Skip own receipter of own event - sign own events not receipt them
                    debug!(
                        "Kevery process: skipped own receipt attachment on own event receipt={}",
                        serder.said().unwrap_or_default()
                    );
                    debug!("Event=\n{}\n", serder.pretty(None));
                    continue;
                }

                if !local {
                    // Skip own receipt on other event when not local
                    debug!("Kevery process: skipped own receipt attachment on nonlocal event receipt={}",
                          serder.said().unwrap_or_default());
                    debug!("Event=\n{}\n", serder.pretty(None));
                    continue;
                }
            }

            // Verify signature
            if cigar
                .verfer
                .clone()
                .unwrap()
                .verify(&cigar.raw(), &lserder.raw())?
            {
                // Get witness list for the event
                let wits = self.fetch_witness_state(&pre, sn)?;
                let rpre = cigar.verfer.clone().unwrap().qb64(); // prefix of receiptor

                if wits.contains(&rpre) {
                    // It's a witness receipt, write in .wigs
                    let index = wits.iter().position(|w| w == &rpre).ok_or_else(|| {
                        KERIError::ValueError("Witness not found in witness list".to_string())
                    })?;

                    // Create witness indexed signature
                    let wiger = Siger::new(
                        Some(cigar.raw().clone()),
                        None,
                        Some(index as u32),
                        None,
                        cigar.verfer.clone(),
                    )?;

                    // Write to db
                    self.db.wigs.add(&[&dg_key], &wiger.qb64().as_bytes())?;
                } else {
                    // Not witness receipt, write receipt couple to database .rcts
                    let couple = [
                        cigar.verfer.clone().unwrap().qb64().as_bytes(),
                        cigar.qb64().as_bytes(),
                    ]
                    .concat();
                    self.db.rcts.add(&[&dg_key], &couple)?;
                }
            }
        }

        Ok(())
    }

    /// Escrow unverified receipt
    fn escrow_u_receipt(
        &self,
        _serder: &SerderKERI,
        _cigars: &[Cigar],
        said: &str,
    ) -> Result<(), KERIError> {
        // Implementation details would go here
        // This would store the receipt in an escrow database to be processed later
        // when the event it's receipting becomes available

        // For now we'll just log it
        debug!("Escrowing unverified receipt for event with SAID: {}", said);

        // TODO: Implement proper escrow functionality
        Ok(())
    }
    /// Escrow unverified witness receipt
    fn escrow_uw_receipt(
        &self,
        _serder: &SerderKERI,
        _wigers: &[Siger],
        said: &str,
    ) -> Result<(), KERIError> {
        // Implementation details would go here
        // This would store the receipt in an escrow database to be processed later
        // when the event it's receipting becomes available

        // For now we'll just log it
        debug!(
            "Escrowing unverified witness receipt for event with SAID: {}",
            said
        );

        // TODO: Implement proper escrow functionality
        Ok(())
    }

    /// Process query mode replay message for collective or single element query.
    /// Assume promiscuous mode for now.
    ///
    /// # Parameters
    /// * `serder` - Query message serder
    /// * `source` - Identifier prefix of querier (optional)
    /// * `sigers` - List of Siger instances of attached controller indexed sigs (optional)
    /// * `cigars` - List of Cigar instances of attached non-trans sigs (optional)
    pub fn process_query(
        &mut self,
        serder: SerderKERI,
        source: Option<Prefixer>,
        sigers: Option<Vec<Siger>>,
        cigars: Option<Vec<Cigar>>,
    ) -> Result<(), KERIError> {
        let ked = serder.ked();

        let ilk = ked
            .get("t")
            .ok_or_else(|| KERIError::ValueError("Missing ilk (t) in query".to_string()))?
            .as_str()
            .ok_or_else(|| KERIError::ValueError("Ilk (t) field is not a string".to_string()))?;

        let route = ked
            .get("r")
            .ok_or_else(|| KERIError::ValueError("Missing route (r) in query".to_string()))?
            .as_str()
            .ok_or_else(|| KERIError::ValueError("Route (r) field is not a string".to_string()))?;

        let qry = ked
            .get("q")
            .ok_or_else(|| KERIError::ValueError("Missing query data (q) in query".to_string()))?
            .as_object()
            .ok_or_else(|| {
                KERIError::ValueError("Query data (q) field is not an object".to_string())
            })?;

        // Determine the destination for replies
        let dest = match (&source, &cigars) {
            (None, Some(cigars)) if !cigars.is_empty() => cigars[0].clone().verfer.unwrap().qb64(),
            (Some(source), _) => source.qb64(),
            _ => {
                return Err(
                    KERIError::ValueError("No valid destination for reply".to_string()).into(),
                )
            }
        };

        match route {
            "logs" => {
                // Extract query parameters
                let pre = qry
                    .get("i")
                    .ok_or_else(|| {
                        KERIError::ValueError("Missing identifier (i) in query".to_string())
                    })?
                    .as_str()
                    .ok_or_else(|| {
                        KERIError::ValueError("Identifier (i) field is not a string".to_string())
                    })?;

                let src = qry
                    .get("src")
                    .ok_or_else(|| {
                        KERIError::ValueError("Missing source (src) in query".to_string())
                    })?
                    .as_str()
                    .ok_or_else(|| {
                        KERIError::ValueError("Source (src) field is not a string".to_string())
                    })?;

                // Optional parameters
                let anchor = qry.get("a").and_then(|v| v.as_str());
                let sn = qry
                    .get("s")
                    .and_then(|v| v.as_str())
                    .map(|s| i64::from_str_radix(s, 16))
                    .transpose()
                    .map_err(|_| {
                        KERIError::ValueError("Invalid sequence number format".to_string())
                    })?;
                let fn_num = qry
                    .get("fn")
                    .and_then(|v| v.as_str())
                    .map(|s| i64::from_str_radix(s, 16))
                    .transpose()
                    .map_err(|_| {
                        KERIError::ValueError("Invalid first seen number format".to_string())
                    })?
                    .unwrap_or(0);

                // Check if we have the identifier
                if !self.kevers.contains_key(pre) {
                    self.escrow_query_not_found_event(
                        &serder,
                        source.as_ref(),
                        sigers.as_deref(),
                        cigars.as_deref(),
                    )?;
                    let msg = format!(
                        "Query not found error on event route={} SAID={}",
                        route,
                        serder.said().unwrap_or_default()
                    );
                    debug!("{}", msg);
                    debug!("Query Body=\n{}\n", serder.pretty(None));
                    return Err(KERIError::QueryNotFoundError(msg).into());
                }

                let kever = &self.kevers[pre];

                // Check anchor if provided
                if let Some(anchor) = anchor {
                    if !self.db.fetch_all_sealing_event_by_event_seal(pre, anchor)? {
                        self.escrow_query_not_found_event(
                            &serder,
                            source.as_ref(),
                            sigers.as_deref(),
                            cigars.as_deref(),
                        )?;
                        let msg = format!(
                            "Query not found error on event route={} SAID={}",
                            route,
                            serder.said().unwrap_or_default()
                        );
                        debug!("{}", msg);
                        debug!("Query Body=\n{}\n", serder.pretty(None));
                        return Err(KERIError::QueryNotFoundError(msg).into());
                    }
                }
                // Check sequence number if provided
                else if let Some(sn) = sn {
                    let current_sn = kever.sner().map(|s| s.num()).unwrap_or_default();
                    if current_sn < sn as u128 || !self.fully_witnessed(&kever.serder().unwrap()) {
                        self.escrow_query_not_found_event(
                            &serder,
                            source.as_ref(),
                            sigers.as_deref(),
                            cigars.as_deref(),
                        )?;
                        let msg = format!(
                            "Query not found error on event route={} SAID={}",
                            route,
                            serder.said().unwrap_or_default()
                        );
                        debug!("{}", msg);
                        debug!("Query Body=\n{}\n", serder.pretty(None));
                        return Err(KERIError::QueryNotFoundError(msg).into());
                    }
                }

                // Get messages to replay
                let mut msgs = Vec::new();

                // Clone prefix events starting from fn_num
                for msg in self.db.clone_pre_iter(pre, Some(fn_num as u64))? {
                    msgs.push(msg);
                }

                // If there's a delegator prefix, clone its events as well
                if let Some(delpre) = kever.delpre() {
                    for msg in self.db.clone_pre_iter(&delpre, Some(0))? {
                        msgs.push(msg);
                    }
                }

                // If we have messages to send, add a replay cue
                if !msgs.is_empty() {
                    let cue = Cue {
                        kin: "replay".to_string(),
                        serder,
                    };
                    self.cues.push_back(cue);
                }
            }

            "ksn" => {
                // Extract query parameters
                let pre = qry
                    .get("i")
                    .ok_or_else(|| {
                        KERIError::ValueError("Missing identifier (i) in query".to_string())
                    })?
                    .as_str()
                    .ok_or_else(|| {
                        KERIError::ValueError("Identifier (i) field is not a string".to_string())
                    })?;

                let src = qry
                    .get("src")
                    .ok_or_else(|| {
                        KERIError::ValueError("Missing source (src) in query".to_string())
                    })?
                    .as_str()
                    .ok_or_else(|| {
                        KERIError::ValueError("Source (src) field is not a string".to_string())
                    })?;

                // Check if we have the identifier
                if !self.kevers.contains_key(pre) {
                    self.escrow_query_not_found_event(
                        &serder,
                        source.as_ref(),
                        sigers.as_deref(),
                        cigars.as_deref(),
                    )?;
                    let msg = format!(
                        "Query not found error on event route={} SAID={}",
                        route,
                        serder.said().unwrap_or_default()
                    );
                    debug!("{}", msg);
                    debug!("Query Body=\n{}\n", serder.pretty(None));
                    return Err(KERIError::QueryNotFoundError(msg).into());
                }

                let kever = &self.kevers[pre];

                // Get list of witness signatures to ensure we are presenting a fully witnessed event
                let dg_key = dg_key(pre, &kever.serder().unwrap().said().unwrap_or_default());
                let wigs = self.db.wigs.get_item_iter(&[&dg_key], false)?;
                let wigers: Vec<Siger> = wigs
                    .iter()
                    .map(|(_, wig)| Siger::from_qb64(&String::from_utf8_lossy(wig), None))
                    .collect::<Result<Vec<Siger>, _>>()?;

                // Check if we have enough witness signatures
                if let Some(toader) = kever.toader() {
                    if wigers.len() < toader.num() as usize {
                        self.escrow_query_not_found_event(
                            &serder,
                            source.as_ref(),
                            sigers.as_deref(),
                            cigars.as_deref(),
                        )?;
                        let msg = format!(
                            "Query not found error on event route={} SAID={}",
                            route,
                            serder.said().unwrap_or_default()
                        );
                        debug!("{}", msg);
                        debug!("Query Body=\n{}\n", serder.pretty(None));
                        return Err(KERIError::QueryNotFoundError(msg).into());
                    }
                }

                // Create reply with key state
                let _state = kever.state();
                let rserder = ReplyEventBuilder::new()
                    .with_route(format!("/ksn/{}", src))
                    .build()?;
                // Add reply cue
                let cue = Cue {
                    kin: "reply".to_string(),
                    serder: rserder,
                };
                self.cues.push_back(cue);
            }

            "mbx" => {
                // Extract query parameters
                let pre = qry
                    .get("i")
                    .ok_or_else(|| {
                        KERIError::ValueError("Missing identifier (i) in query".to_string())
                    })?
                    .as_str()
                    .ok_or_else(|| {
                        KERIError::ValueError("Identifier (i) field is not a string".to_string())
                    })?;

                let src = qry
                    .get("src")
                    .ok_or_else(|| {
                        KERIError::ValueError("Missing source (src) in query".to_string())
                    })?
                    .as_str()
                    .ok_or_else(|| {
                        KERIError::ValueError("Source (src) field is not a string".to_string())
                    })?;

                let topics = qry
                    .get("topics")
                    .ok_or_else(|| KERIError::ValueError("Missing topics in query".to_string()))?
                    .as_array()
                    .ok_or_else(|| {
                        KERIError::ValueError("Topics field is not an array".to_string())
                    })?
                    .iter()
                    .map(|v| v.as_str().unwrap_or_default().to_string())
                    .collect::<Vec<String>>();

                // Check if we have the identifier
                if !self.kevers.contains_key(pre) {
                    self.escrow_query_not_found_event(
                        &serder,
                        source.as_ref(),
                        sigers.as_deref(),
                        cigars.as_deref(),
                    )?;
                    let msg = format!(
                        "Query not found error on event route={} SAID={}",
                        route,
                        serder.said().unwrap_or_default()
                    );
                    debug!("{}", msg);
                    debug!("Query Body=\n{}\n", serder.pretty(None));
                    return Err(KERIError::QueryNotFoundError(msg).into());
                }

                // Add stream cue
                let cue = Cue {
                    kin: "stream".to_string(),
                    serder,
                };
                self.cues.push_back(cue);
            }

            _ => {
                // Invalid route
                let cue = Cue {
                    kin: "route".to_string(),
                    serder: serder.clone(),
                };
                self.cues.push_back(cue);

                let msg = format!(
                    "Invalid query message {} for event route={} SAID={}",
                    ilk,
                    route,
                    serder.said().unwrap_or_default()
                );
                info!("{}", msg);
                debug!("Query Body=\n{}\n", serder.pretty(None));

                return Err(KERIError::ValueError(msg).into());
            }
        }

        Ok(())
    }

    pub fn fully_witnessed(&self, serder: &SerderKERI) -> bool {
        let preb = serder.preb().unwrap_or_default();
        let said = serder.said().unwrap_or_default();

        let key = dg_key(preb, said);
        match self.db.wigs.get::<_, Vec<u8>>(&[&key]) {
            Ok(wigs) => {
                let pre = serder.pre().unwrap();
                let kever = &self.kevers[&pre];
                let toad = kever.toader().unwrap().num();
                !wigs.len() < toad as usize
            }
            Err(_) => false,
        }
    }

    /// Escrow a query that couldn't be processed because the requested event wasn't found
    fn escrow_query_not_found_event(
        &self,
        serder: &SerderKERI,
        _source: Option<&Prefixer>,
        _sigers: Option<&[Siger]>,
        _cigars: Option<&[Cigar]>,
    ) -> Result<(), KERIError> {
        // Implementation details would go here
        // This would store the query in an escrow database to be processed later
        // when the requested event becomes available

        // For now we'll just log it
        debug!(
            "Escrowing query not found event with SAID: {}",
            serder.said().unwrap_or_default()
        );

        // TODO: Implement proper escrow functionality
        Ok(())
    }
}

/// Builder pattern for Kevery to make initialization more ergonomic
pub struct KeveryBuilder<'db> {
    db: Arc<&'db Baser<'db>>,
    cues: Option<VecDeque<Cue>>,
    rvy: Option<Rvy<'db>>,
    lax: Option<bool>,
    local: Option<bool>,
    cloned: Option<bool>,
    direct: Option<bool>,
    check: Option<bool>,
}

impl<'db> KeveryBuilder<'db> {
    /// Create a new KeveryBuilder instance
    pub fn new(db: Arc<&'db Baser<'db>>) -> Self {
        Self {
            db,
            cues: None,
            rvy: None,
            lax: None,
            local: None,
            cloned: None,
            direct: None,
            check: None,
        }
    }

    /// Set the cues for the Kevery instance
    pub fn with_cues(mut self, cues: VecDeque<Cue>) -> Self {
        self.cues = Some(cues);
        self
    }

    /// Set the recovery module for the Kevery instance
    pub fn with_rvy(mut self, rvy: Rvy<'db>) -> Self {
        self.rvy = Some(rvy);
        self
    }

    /// Set the lax mode for the Kevery instance
    pub fn with_lax(mut self, lax: bool) -> Self {
        self.lax = Some(lax);
        self
    }

    /// Set the local flag for the Kevery instance
    pub fn with_local(mut self, local: bool) -> Self {
        self.local = Some(local);
        self
    }

    /// Set the cloned flag for the Kevery instance
    pub fn with_cloned(mut self, cloned: bool) -> Self {
        self.cloned = Some(cloned);
        self
    }

    /// Set the direct mode for the Kevery instance
    pub fn with_direct(mut self, direct: bool) -> Self {
        self.direct = Some(direct);
        self
    }

    /// Set the check mode for the Kevery instance
    pub fn with_check(mut self, check: bool) -> Self {
        self.check = Some(check);
        self
    }

    /// Build the Kevery instance from the provided options
    pub fn build(self) -> Result<Kevery<'db>, KERIError> {
        Kevery::new(
            self.cues,
            self.db.clone(),
            self.rvy,
            self.lax,
            self.local,
            self.cloned,
            self.direct,
            self.check,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keri::db::dbing::LMDBer;

    #[test]
    fn test_kevery_new() -> Result<(), KERIError> {
        // Create a temporary database
        let lmdber = &LMDBer::builder()
            .temp(true)
            .name("test_kevery")
            .build()
            .map_err(|e| KERIError::DatabaseError(format!("{}", e)))?;

        let db =
            Baser::new(Arc::new(lmdber)).map_err(|e| KERIError::DatabaseError(format!("{}", e)))?;

        // Create Kevery using the new function
        let kevery = Kevery::new(
            None,
            Arc::new(&db),
            None,
            Some(true),
            Some(false),
            Some(false),
            Some(true),
            Some(false),
        )?;

        assert!(kevery.lax);
        assert!(!kevery.local);
        assert!(!kevery.cloned);
        assert!(kevery.direct);
        assert!(!kevery.check);
        assert!(kevery.kevers().is_empty());

        Ok(())
    }

    #[test]
    fn test_kevery_builder() -> Result<(), KERIError> {
        // Create a temporary database
        let lmdber = &LMDBer::builder()
            .temp(true)
            .name("test_kevery_builder")
            .build()
            .map_err(|e| KERIError::DatabaseError(format!("{}", e)))?;

        let db =
            Baser::new(Arc::new(lmdber)).map_err(|e| KERIError::DatabaseError(format!("{}", e)))?;

        // Create Kevery using the builder pattern
        let kevery = KeveryBuilder::new(Arc::new(&db))
            .with_lax(true)
            .with_local(false)
            .with_cloned(false)
            .with_direct(true)
            .with_check(false)
            .build()?;

        assert!(kevery.lax);
        assert!(!kevery.local);
        assert!(!kevery.cloned);
        assert!(kevery.direct);
        assert!(!kevery.check);
        assert!(kevery.kevers().is_empty());

        Ok(())
    }
}
