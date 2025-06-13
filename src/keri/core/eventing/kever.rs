use crate::cesr::dater::Dater;
use crate::cesr::diger::Diger;
use crate::cesr::indexing::siger::Siger;
use crate::cesr::indexing::Indexer;
use crate::cesr::number::Number;
use crate::cesr::prefixer::Prefixer;
use crate::cesr::saider::Saider;
use crate::cesr::seqner::Seqner;
use crate::cesr::tholder::{Tholder, TholderSith};
use crate::cesr::trait_dex;
use crate::cesr::verfer::Verfer;
use crate::keri::core::eventing::state::StateEventBuilder;
use crate::keri::core::eventing::verify_sigs;
use crate::keri::core::serdering::{Rawifiable, SadValue, Serder, SerderKERI};
use crate::keri::db::basing::{Baser, EventSourceRecord, KeyStateRecord, StateEERecord};
use crate::keri::db::dbing::keys::{dg_key, sn_key};
use crate::keri::{Ilk, KERIError};
use crate::Matter;
use num_bigint::BigUint;
use std::collections::HashSet;
use std::sync::Arc;

/// Represents the location of the last establishment event
#[derive(Debug, Clone, PartialEq)]
pub struct LastEstLoc {
    /// Sequence number
    pub s: u64,
    /// Digest (said)
    pub d: String,
}

pub struct Kever<'db> {
    pub db: Arc<&'db Baser<'db>>,
    version: String,        // Version of KERI protocol
    ilk: Ilk,               // Event type ilk
    delpre: Option<String>, // Delegator prefix if any
    delegated: bool,        // True if delegated event, False otherwise
    fner: Option<Number>,   // First seen ordinal number
    dater: Option<Dater>,   // First seen timestamp

    // Fields needed for inception
    sner: Option<Number>,
    verfers: Option<Vec<Verfer>>,
    tholder: Option<Tholder>,
    prefixer: Option<Prefixer>,
    serder: Option<SerderKERI>,
    ndigers: Option<Vec<Diger>>,
    ntholder: Option<Tholder>,
    cuts: Option<Vec<String>>,
    adds: Option<Vec<String>>,
    wits: Option<Vec<String>>,
    toader: Option<Number>,
    last_est: Option<LastEstLoc>,

    // Configuration traits
    est_only: Option<bool>,
    do_not_delegate: Option<bool>,
}

impl<'db> Kever<'db> {
    /// Create a new Kever instance for an inception event
    ///
    /// # Arguments
    ///
    /// * `state` - Optional key state record
    /// * `serder` - Optional serialized event data
    /// * `sigers` - Optional list of indexed controller signatures
    /// * `wigers` - Optional list of indexed witness signatures
    /// * `db` - LMDB database instance
    /// * `est_only` - Optional boolean, True means establishment only events allowed
    /// * `delseqner` - Optional delegating event sequence number
    /// * `delsaider` - Optional delegating event SAID
    /// * `firner` - Optional first seen ordinal number
    /// * `dater` - Optional first seen timestamp
    /// * `cues` - Optional queue for notices or requests
    /// * `eager` - Optional boolean for eager validation
    /// * `local` - Optional boolean for event source validation logic
    /// * `check` - Optional boolean for database update control
    ///
    /// # Returns
    ///
    /// * `Result<Self, KERIError>` - New Kever instance or error
    pub fn new(
        db: Arc<&'db Baser<'db>>,
        state: Option<KeyStateRecord>,
        serder: Option<SerderKERI>,
        sigers: Option<Vec<Siger>>,
        wigers: Option<Vec<Siger>>,
        est_only: Option<bool>,
        delseqner: Option<Seqner>,
        delsaider: Option<Saider>,
        firner: Option<Seqner>,
        dater: Option<Dater>,
        eager: Option<bool>,
        local: Option<bool>,
        check: Option<bool>,
    ) -> Result<Self, KERIError> {
        // Validate required arguments
        if state.is_none() && (serder.is_none() || sigers.is_none()) {
            return Err(KERIError::ValueError(
                "Missing required arguments. Need state or serder and sigers".to_string(),
            ));
        }

        // Default values
        let eager = eager.unwrap_or(false);
        let local = local.unwrap_or(true);
        let check = check.unwrap_or(false);

        if let Some(state) = state {
            // Preload from state
            return Self::reload(db, state);
        }

        // Unwrap serder since we know it exists at this point
        let serder = serder.unwrap();
        let sigers = sigers.unwrap();

        // Get version and validate
        let version = serder.version().clone();

        // Get ilk and validate
        let ilk = serder.ilk().unwrap().clone();
        if ilk != Ilk::Icp && ilk != Ilk::Dip {
            return Err(KERIError::ValidationError(format!(
                "Expected ilk = icp or dip, got {} for evt = {:?}",
                ilk,
                serder.ked()
            )));
        }

        // Create Kever with basic fields
        let mut kever = Kever {
            db,
            version: format!("{}", version),
            ilk,
            delpre: None,
            delegated: false,
            fner: None,
            dater: None,
            sner: None,
            verfers: None,
            tholder: None,
            prefixer: None,
            serder: None,
            ndigers: None,
            ntholder: None,
            cuts: None,
            adds: None,
            wits: None,
            toader: None,
            last_est: None,
            est_only: None,
            do_not_delegate: None,
            // Initialize other fields here
        };

        // Do major event validation and state setting
        kever.incept(serder.clone())?;

        // Assign config traits perms
        kever.config(serder.clone(), est_only)?;

        // Validates signers, delegation if any, and witnessing when applicable
        let (sigers, wigers, delpre, delseqner, delsaider) = kever.val_sigs_wigs_del(
            serder.clone(),
            sigers,
            serder.verfers().clone(),
            kever.tholder().unwrap(),
            wigers,
            kever.toader(),
            kever.wits().clone(),
            delseqner,
            delsaider,
            eager,
            local,
        )?;

        // Set delegation fields
        kever.delpre = delpre;
        kever.delegated = kever.delpre.is_some();

        // Get witnesses from serder
        let wits = serder.backs().clone();

        // Log event and get first seen data
        let (fn_num, dts) = kever.log_event(
            serder, sigers, wigers, wits, !check, delseqner, delsaider, firner, dater, local,
        )?;

        // Set first seen data if not in check mode
        if let Some(fn_num) = fn_num {
            kever.fner = Some(Number::from_num(&BigUint::from(fn_num))?);
            kever.dater = Some(Dater::from_dt(dts));
            let _ = kever
                .db
                .states
                .pin(&[kever.prefixer().unwrap().qb64()], &kever.state()?);
        }

        Ok(kever)
    }

    /// Reload Kever attributes (aka its state) from state (KeyStateRecord)
    ///
    /// # Arguments
    ///
    /// * `state` - Instance of KeyStateRecord containing key state information
    ///
    /// # Returns
    ///
    /// * `Result<Self, KERIError>` - New Kever instance initialized from state or error
    pub fn reload(db: Arc<&'db Baser<'db>>, state: KeyStateRecord) -> Result<Self, KERIError> {
        // Create a Prefixer from the identifier prefix
        let prefixer = Prefixer::from_qb64(&state.i)
            .map_err(|e| KERIError::ValueError(format!("Invalid identifier prefix: {}", e)))?;

        // Create sequence number from hexadecimal string
        let sner = Number::from_numh(&state.s)
            .map_err(|e| KERIError::ValueError(format!("Invalid sequence number: {}", e)))?;

        // Create first seen ordinal number from hexadecimal string
        let fner = Number::from_numh(&state.f)
            .map_err(|e| KERIError::ValueError(format!("Invalid first seen number: {}", e)))?;

        // Create datetime stamp
        let dater = Dater::from_dt((&state.dt).parse().unwrap());

        // Get event type (ilk)
        let ilk = match Ilk::from_str(&state.et) {
            Some(i) => i,
            None => {
                return Err(KERIError::ValueError(format!(
                    "Invalid event type: {}",
                    state.et
                )))
            }
        };

        // Create signing threshold holder
        let tholder = Tholder::new(
            None,
            None,
            Some(TholderSith::from_sad_value(SadValue::String(state.kt))?),
        )?;

        // Create next threshold holder
        let ntholder = Tholder::new(
            None,
            None,
            Some(TholderSith::from_sad_value(SadValue::String(state.nt))?),
        )?;

        // Create verifiers from signing keys
        let verfers = state
            .k
            .iter()
            .map(|key| Verfer::from_qb64(key))
            .collect::<Result<Vec<Verfer>, _>>()
            .map_err(|e| KERIError::ValueError(format!("Invalid signing key: {}", e)))?;

        // Create digers from next keys
        let ndigers = state
            .n
            .iter()
            .map(|dig| Diger::from_qb64(dig))
            .collect::<Result<Vec<Diger>, _>>()
            .map_err(|e| {
                KERIError::ValueError(format!("Invalid next signing key digest: {}", e))
            })?;

        // Create witness threshold
        let toader = Number::from_numh(&state.bt)
            .map_err(|e| KERIError::ValueError(format!("Invalid witness threshold: {}", e)))?;

        // Get witnesses
        let wits = state.b.clone();

        // Get cuts and adds from establishment event record
        let cuts = state.ee.br.clone().unwrap_or_default();
        let adds = state.ee.ba.clone().unwrap_or_default();

        // Create configuration traits
        let est_only = state.c.contains(&"EstOnly".to_string());
        let do_not_delegate = state.c.contains(&"DoNotDelegate".to_string());

        // Create last establishment event location
        let last_est_sn = u64::from_str_radix(&state.ee.s, 16).map_err(|e| {
            KERIError::ValueError(format!("Invalid last establishment sequence number: {}", e))
        })?;

        let last_est = LastEstLoc {
            s: last_est_sn,
            d: state.ee.d.clone(),
        };

        // Get delegator prefix if any
        let delpre = if state.di.is_empty() {
            None
        } else {
            Some(state.di.clone())
        };
        let delegated = delpre.is_some();

        // In a complete implementation, the code below would retrieve the event from the database
        // and create the serder, then construct and return the Kever

        // Get the corresponding event from the database
        let key = dg_key(prefixer.qb64(), state.d.clone());

        let raw = match db.evts.get::<_, Vec<u8>>(&[key]) {
            Ok(Some(data)) => data,
            _ => {
                return Err(KERIError::DatabaseError(format!(
                    "Corresponding event not found for state={:?}",
                    prefixer.qb64()
                )))
            }
        };

        // Create SerderKERI from raw bytes
        let serder = SerderKERI::from_raw(&raw, None)
            .map_err(|e| KERIError::ValueError(format!("Invalid event serder: {}", e)))?;

        // Create and return Kever instance with all components
        Ok(Kever {
            db,
            version: format!("{}.{}", state.vn[0], state.vn[1]), // Convert version numbers to string
            ilk,
            delpre,
            delegated,
            fner: Some(fner),
            dater: Some(dater),
            sner: Some(sner),
            verfers: Some(verfers),
            tholder: Some(tholder),
            prefixer: Some(prefixer),
            serder: Some(serder),
            ndigers: Some(ndigers),
            ntholder: Some(ntholder),
            cuts: Some(cuts),
            adds: Some(adds),
            wits: Some(wits),
            toader: Some(toader),
            last_est: Some(last_est),
            est_only: Some(est_only),
            do_not_delegate: Some(do_not_delegate),
        })
    }

    /// Verify inception key event message from serder
    ///
    /// # Arguments
    ///
    /// * `serder` - SerderKERI instance of inception event
    ///
    /// # Returns
    ///
    /// * `Result<(), KERIError>` - Success or error
    fn incept(&mut self, serder: SerderKERI) -> Result<(), KERIError> {
        // Get event data
        let ked = serder.sad();

        // Check sequence number
        let sner = serder.sner().ok_or_else(|| {
            KERIError::ValidationError("Missing sequence number in inception event".to_string())
        })?;

        // Ensure sequence number is 0 for inception
        if sner.num() > 0 {
            return Err(KERIError::ValidationError(format!(
                "Nonzero sn={} in inception event.",
                sner.num()
            )));
        }

        // Get and validate verifiers
        let verfers = serder.verfers().ok_or_else(|| {
            KERIError::ValidationError("Missing verifiers in inception event".to_string())
        })?;

        // Get and validate threshold holder
        let tholder = serder.tholder().ok_or_else(|| {
            KERIError::ValidationError("Missing threshold in inception event".to_string())
        })?;

        // Check if threshold size is valid for number of keys
        if verfers.len() < tholder.size() {
            return Err(KERIError::ValidationError(format!(
                "Invalid sith = {:?} for keys = {:?} for evt = {:?}.",
                tholder.sith(),
                verfers.iter().map(|v| v.qb64()).collect::<Vec<String>>(),
                ked
            )));
        }

        // Extract and validate prefixer
        let prefixer = Prefixer::from_qb64(&serder.pre().unwrap())?;

        // Get and validate next digest list
        let ndigs = serder.ndigs().unwrap_or_default();
        if !prefixer.transferable() && !ndigs.is_empty() {
            return Err(KERIError::ValidationError(
                format!("Invalid inception next digest list not empty for non-transferable prefix = {} for evt = {:?}.",
                        prefixer.qb64(), ked)
            ));
        }

        // Get next digest verifiers
        let ndigers = serder.ndigers().unwrap_or_default();

        // Get next threshold holder
        let ntholder = serder.ntholder();

        // Cuts and adds are always empty at inception since no previous event
        let cuts: Vec<String> = Vec::new();
        let adds: Vec<String> = Vec::new();

        // Get and validate witnesses
        let wits = serder.backs().unwrap_or_default();

        if !prefixer.transferable() && !wits.is_empty() {
            return Err(KERIError::ValidationError(format!(
                "Invalid inception wits not empty for non-transferable prefix = {} for evt = {:?}.",
                prefixer.qb64(),
                ked
            )));
        }

        // Check for duplicate witnesses
        let mut unique_wits = HashSet::new();
        for wit in &wits {
            if !unique_wits.insert(wit) {
                return Err(KERIError::ValidationError(format!(
                    "Invalid backers = {:?}, has duplicates for evt = {:?}.",
                    wits, ked
                )));
            }
        }

        // Get and validate toad (threshold of accountable duplicity)
        let sad = serder.sad();
        let bt_hex = sad.get("bt").and_then(|v| v.as_str()).ok_or_else(|| {
            KERIError::ValidationError("Missing bt in inception event".to_string())
        })?;

        let toader = Number::from_num(&BigUint::from(
            u64::from_str_radix(bt_hex, 16)
                .map_err(|e| KERIError::ValueError(format!("Invalid hex in ion: {}", e)))?,
        ))?;
        let toad_num = toader.num() as usize;

        if !wits.is_empty() {
            if toad_num < 1 || toad_num > wits.len() {
                return Err(KERIError::ValueError(format!(
                    "Invalid toad = {} for backers (wits)={:?} for event={:?}.",
                    toad_num, wits, ked
                )));
            }
        } else {
            if toad_num != 0 {
                return Err(KERIError::ValueError(format!(
                    "Invalid toad = {} for backers (wits)={:?} for event={:?}.",
                    toad_num, wits, ked
                )));
            }
        }

        // Check data field for non-transferable prefixes
        let data = serder.sad().get("a").cloned();
        if !prefixer.transferable() && data.is_some() {
            return Err(KERIError::ValidationError(format!(
                "Invalid inception data not empty for non-transferable prefix = {} for evt = {:?}.",
                prefixer.qb64(),
                ked
            )));
        }

        // Last establishment event location (needed for recovery events and transferable receipts)
        let last_est = LastEstLoc {
            s: sner.num() as u64,
            d: serder.said().unwrap_or_default().to_string(),
        };

        // Store all the validated fields into the Kever instance
        self.sner = Some(sner);
        self.verfers = Some(verfers);
        self.tholder = Some(tholder);
        self.prefixer = Some(prefixer);
        self.serder = Some(serder.clone());
        self.ndigers = Some(ndigers);
        self.ntholder = ntholder;
        self.cuts = Some(cuts);
        self.adds = Some(adds);
        self.wits = Some(wits);
        self.toader = Some(toader);
        self.last_est = Some(last_est);

        Ok(())
    }

    /// Process configuration traits from the serder
    ///
    /// # Arguments
    ///
    /// * `serder` - The SerderKERI containing configuration traits
    /// * `est_only` - Optional boolean to override the EstOnly trait setting
    ///
    /// # Returns
    ///
    /// * `Result<(), KERIError>` - Success or error
    fn config(&mut self, serder: SerderKERI, est_only: Option<bool>) -> Result<(), KERIError> {
        // We need to add these fields to the Kever struct
        // Add constants for default values
        const EST_ONLY: bool = false;
        const DO_NOT_DELEGATE: bool = false;

        // Assign traits with proper default values
        // Use provided est_only if available, otherwise use default or current value
        self.est_only = match est_only {
            Some(value) => Some(value),
            None => Some(self.est_only.unwrap_or(EST_ONLY)),
        };

        // For do_not_delegate, we'll use the current value or default
        self.do_not_delegate = Some(self.do_not_delegate.unwrap_or(DO_NOT_DELEGATE));

        // Process configuration traits from the serder
        if let Some(traits) = serder.traits() {
            // In Rust we need to check the type of traits and process accordingly
            if let Some(traits_array) = traits.as_array() {
                // Process each trait in the array
                for trait_value in traits_array {
                    if let Some(trait_str) = trait_value.as_str() {
                        match trait_str {
                            // Using string literals here, but should use proper TraitDex enum
                            "EO" => self.est_only = Some(true),
                            "DND" => self.do_not_delegate = Some(true),
                            _ => (), // Ignore unknown traits
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Validates signatures, witnesses, and delegation
    ///
    /// Returns tuple (sigers, wigers, delpre, delseqner, delsaider) where:
    /// - sigers: Vec of validated signature verified members of input sigers
    /// - wigers: Option<Vec> of validated signature verified members of input wigers
    /// - delpre: Option<String> delegator prefix if delegated else None
    /// - delseqner: Option<Seqner> delegating event sequence number
    /// - delsaider: Option<Saider> delegating event SAID
    ///
    /// # Arguments
    ///
    /// * `serder` - Serialized event data
    /// * `sigers` - List of indexed controller signatures
    /// * `verfers` - List of verifiers from latest est event
    /// * `tholder` - Threshold holder for signatures
    /// * `wigers` - Optional list of indexed witness signatures
    /// * `toader` - Optional threshold holder for witnesses
    /// * `wits` - List of witness prefixes
    /// * `delseqner` - Optional delegating event sequence number
    /// * `delsaider` - Optional delegating event SAID
    /// * `eager` - Boolean for eager validation
    /// * `local` - Boolean for event source validation logic
    fn val_sigs_wigs_del(
        &self,
        serder: SerderKERI,
        mut sigers: Vec<Siger>,
        verfers: Option<Vec<Verfer>>,
        tholder: Tholder,
        wigers: Option<Vec<Siger>>,
        toader: Option<Number>,
        wits: Vec<String>,
        delseqner: Option<Seqner>,
        delsaider: Option<Saider>,
        eager: bool,
        local: bool,
    ) -> Result<
        (
            Vec<Siger>,
            Option<Vec<Siger>>,
            Option<String>,
            Option<Seqner>,
            Option<Saider>,
        ),
        KERIError,
    > {
        // Unwrap verfers since they are required
        let verfers = match verfers {
            Some(v) => v,
            None => return Err(KERIError::ValueError("Missing verfers".to_string())),
        };

        // Unwrap toader or use default if None
        let toader = match toader {
            Some(t) => t,
            None => Number::from_num(&BigUint::from(0u32))?,
        };

        // Check threshold vs number of keys
        if verfers.len() < tholder.size() {
            return Err(KERIError::ValidationError(format!(
                "Invalid sith = {:?} for keys = {:?} for evt = {:?}",
                tholder.sith(),
                verfers.iter().map(|v| v.qb64()).collect::<Vec<String>>(),
                serder.ked()
            )));
        }

        // Filter sigers for locally membered signatures when not local
        if !local && self.locally_membered(None) {
            if let Some(indices) = self.locally_contributed_indices(&verfers) {
                sigers = sigers
                    .into_iter()
                    .filter(|siger| !indices.contains(&siger.index()))
                    .collect();

                // TODO: Implement cue pushing for remoteMemberedSig if needed
            }
        }

        // Verify signatures and get unique verified sigers and indices
        let (sigers, indices) = verify_sigs(&serder.raw(), sigers, &verfers)?;

        // Check if minimally signed
        if indices.is_empty() {
            return Err(KERIError::ValidationError(format!(
                "No verified signatures for evt = {:?}",
                serder.ked()
            )));
        }

        // Get delegator's delpre if any for misfit check
        let delpre = if serder.ilk() == Some(Ilk::Dip) {
            // Get delegator from dip event
            let delpre = serder.delpre();
            if delpre.is_none() {
                return Err(KERIError::ValidationError(format!(
                    "Empty or missing delegator for delegated inception event = {:?}",
                    serder.ked()
                )));
            }
            delpre
        } else if serder.ilk() == Some(Ilk::Drt) {
            // Get delegator from kever state
            self.delpre.clone()
        } else {
            // Not delegable event (icp, rot, ixn)
            None
        };

        // Misfit escrow checks
        if !local
            && (self.locally_owned(None)
                || self.locally_witnessed(Some(&wits), None)
                || self.locally_delegated(delpre.as_deref()))
        {
            self.escrow_mf_event(
                &serder,
                sigers,
                wigers,
                delseqner.as_ref(),
                delsaider.as_ref(),
                local,
            )?;

            return Err(KERIError::ValidationError(format!(
                "Nonlocal source for locally owned or locally witnessed or locally delegated event={:?}, local aids={:?}, wits={:?}, delegator={:?}",
                serder.ked(),
                self.db.prefixes,
                wits,
                delpre
            )));
        }

        // Convert witness prefixes to verifiers
        let werfers: Vec<Verfer> = wits
            .iter()
            .map(|wit| Verfer::new(Some(wit.as_bytes()), None))
            .collect::<Result<Vec<Verfer>, _>>()?;

        // Verify witness signatures
        let (wigers, windices) = match wigers {
            Some(wigers) => {
                let (wigers, windices) = verify_sigs(&serder.raw(), wigers, &werfers)?;
                (Some(wigers), windices)
            }
            None => (None, vec![]),
        };

        // Check if fully signed vs signing threshold
        let pre = self.prefixer().unwrap().qb64();
        if !tholder.satisfy(&indices) {
            // Escrow partially signed event
            self.escrow_ps_event(
                &serder,
                sigers.clone(),
                wigers,
                delseqner.as_ref(),
                delsaider.as_ref(),
                local,
            )?;

            return Err(KERIError::ValidationError(format!(
                "AID {}...{}: Failure satisfying sith = {:?} on sigs {:?} for evt = {:?}",
                &pre[..4],
                &pre[pre.len() - 4..],
                tholder.sith(),
                sigers.iter().map(|s| s.qb64()).collect::<Vec<String>>(),
                serder.said()
            )));
        }

        // Check if fully signed vs prior next rotation threshold for rotations
        if matches!(serder.ilk(), Some(Ilk::Rot) | Some(Ilk::Drt)) {
            let ondices = self.exposeds(&sigers)?;
            if let Some(ntholder) = self.ntholder.clone() {
                if !ntholder.satisfy(&ondices) {
                    // Escrow partially signed event
                    self.escrow_ps_event(
                        &serder,
                        sigers.clone(),
                        wigers,
                        delseqner.as_ref(),
                        delsaider.as_ref(),
                        local,
                    )?;

                    return Err(KERIError::ValidationError(format!(
                        "AID {}...{}: Failure satisfying prior nsith = {:?} with exposed sigs {:?} for new est evt={:?}",
                        &pre[..4],
                        &pre[pre.len()-4..],
                        ntholder.sith(),
                        sigers.iter().map(|s| s.qb64()).collect::<Vec<String>>(),
                        serder.said()
                    )));
                }
            }
        }

        // Verify witness threshold (toad)
        if wits.is_empty() {
            if toader.num() != 0u128 {
                return Err(KERIError::ValidationError(format!(
                    "Invalid toad = {:?} for wits = {:?}",
                    toader.num(),
                    wits
                )));
            }
        } else {
            // Verify toad if not locally owned, membered, or witnessed
            if !(self.locally_owned(None)
                || self.locally_membered(None)
                || self.locally_witnessed(Some(&wits), None))
            {
                if !wits.is_empty() {
                    if toader.num() < 1 || toader.num() as usize > wits.len() {
                        return Err(KERIError::ValidationError(format!(
                            "Invalid toad = {:?} for wits = {:?}",
                            toader.num(),
                            wits
                        )));
                    }
                } else if toader.num() != 0 {
                    return Err(KERIError::ValidationError(format!(
                        "Invalid toad = {:?} for wits = {:?}",
                        toader.num(),
                        wits
                    )));
                }

                if windices.len() < toader.num() as usize {
                    // Escrow partially witnessed event
                    if self.escrow_pw_event(
                        &serder,
                        wigers.clone(),
                        sigers,
                        delseqner.as_ref(),
                        delsaider.as_ref(),
                        local,
                    )? {
                        // TODO: Push cue to query for witness receipts if needed
                    }

                    return Err(KERIError::ValidationError(format!(
                        "AID {}...{}: Failure satisfying toad={:?} on witness sigs {:?} for event={:?}",
                        &pre[..4],
                        &pre[pre.len()-4..],
                        toader.num(),
                        wigers.map_or(vec![], |w| w.iter().map(|s| s.qb64()).collect::<Vec<String>>()),
                        serder.said()
                    )));
                }
            }
        }

        // Check delegation approval
        if self.locally_delegated(delpre.as_deref()) && !self.locally_owned(None) {
            if delseqner.is_none() || delsaider.is_none() {
                // Escrow delegable event
                self.escrow_delegable_event(&serder, &sigers, wigers, local)?;

                return Err(KERIError::ValidationError(format!(
                    "Missing approval for delegation by {:?} of event = {:?}",
                    delpre,
                    serder.said()
                )));
            }
        }

        // Validate delegation if applicable
        let (delseqner, delsaider) = self.validate_delegation(
            &serder,
            &sigers,
            wigers.clone(),
            &wits,
            delpre.as_deref(),
            delseqner.as_ref(),
            delsaider.as_ref(),
            eager,
            local,
        )?;

        Ok((sigers, wigers, delpre, delseqner, delsaider))
    }

    fn locally_owned(&self, pre: Option<&str>) -> bool {
        match pre {
            Some(pre) => self.db.prefixes.contains(pre) && !self.db.groups.contains(pre),
            None => match self.prefixer() {
                Some(prefixer) => {
                    self.db.prefixes.contains(&prefixer.qb64())
                        && !self.db.groups.contains(&prefixer.qb64())
                }
                None => false,
            },
        }
    }

    fn locally_delegated(&self, delpre: Option<&str>) -> bool {
        match delpre {
            Some(delpre) => self.locally_owned(Some(delpre)),
            None => false,
        }
    }

    fn locally_membered(&self, pre: Option<&str>) -> bool {
        match pre {
            Some(_) => self.db.groups.contains(pre.unwrap()),
            None => match self.prefixer() {
                Some(prefixer) => self.db.groups.contains(&prefixer.qb64()),
                None => false,
            },
        }
    }

    fn locally_contributed_indices(&self, _verfers: &[Verfer]) -> Option<Vec<u32>> {
        todo!("Implement getting indices of locally contributed signatures")
    }

    /// Returns true if a local controller is a witness of this Kever's KEL or the provided witness list
    ///
    /// # Arguments
    /// * `wits` - Optional list of qb64 witness prefixes. If None, uses the current witnesses for this Kever
    /// * `serder` - Optional SerderKERI instance. If provided, derives witnesses from it instead of current state
    ///
    /// # Returns
    /// `true` if any of the prefixes in self.prefixes is also in the witness list; `false` otherwise
    pub fn locally_witnessed(&self, wits: Option<&[String]>, serder: Option<&SerderKERI>) -> bool {
        // Determine which witness list to use
        let witnesses = match (wits, serder) {
            // If both wits and serder are None, use this Kever's witnesses
            (None, None) => self.wits(),

            // If wits is provided, use it directly
            (Some(w), _) => w.to_vec(),

            // If serder is provided but no wits, derive witnesses from serder
            (None, Some(s)) => {
                // Check if serder is for the same KEL as this Kever
                let prefixer = match self.prefixer() {
                    Some(p) => p,
                    None => return false, // No prefixer available
                };

                if s.pre() != Some(prefixer.qb64()) {
                    return false; // Not the same KEL as self
                }

                // In Rust implementation, we need to call a method to derive witnesses from the serder
                match self.derive_backs(s) {
                    Ok((derived_wits, _, _)) => derived_wits,
                    Err(_) => return false, // Error deriving witnesses, return false
                }
            }
        };

        // Check if any local prefixes are in the witness list
        let local_prefix_set: HashSet<_> = self.db.prefixes.iter().collect();
        let witness_set: HashSet<_> = witnesses.iter().collect();

        // Return true if the intersection is not empty
        !local_prefix_set.is_disjoint(&witness_set)
    }

    /// Derives and returns tuple of (wits, cuts, adds) for backers given current set
    /// and any changes provided by serder.
    ///
    /// # Arguments
    /// * `serder` - Instance of current event
    ///
    /// # Returns
    /// A tuple containing:
    /// * `wits` - List of witness prefixes (full list of backers)
    /// * `cuts` - List of witnesses removed in latest establishment event
    /// * `adds` - List of witnesses added in latest establishment event
    ///
    /// # Errors
    /// Returns ValidationError if there are invalid combinations of witnesses, cuts, or adds
    pub fn derive_backs(
        &self,
        serder: &SerderKERI,
    ) -> Result<(Vec<String>, Vec<String>, Vec<String>), KERIError> {
        // Get current ilk from serder
        let ilk = serder.ilk().unwrap();
        let sn = serder.sn().unwrap();

        // If not a rotation or delegation rotation event, or sequence number is not greater,
        // return current values with no changes
        if (ilk != Ilk::Icp && ilk != Ilk::Drt)
            || self.sner.as_ref().map_or(0, |n| n.num()) >= sn as u128
        {
            // Return current values with empty cuts and adds lists
            return Ok((
                self.wits(),
                self.cuts.as_ref().map_or_else(Vec::new, |c| c.clone()),
                self.adds.as_ref().map_or_else(Vec::new, |a| a.clone()),
            ));
        }

        // Get the current witnesses and convert to HashSet for set operations
        let wits = self.wits();
        let wit_set: HashSet<String> = HashSet::from_iter(wits.iter().cloned());

        // Extract cuts from serder
        let cuts = serder.cuts().unwrap_or_else(|| Vec::new());

        // Validate cuts: check for duplicates
        let cut_set: HashSet<String> = HashSet::from_iter(cuts.iter().cloned());
        if cut_set.len() != cuts.len() {
            return Err(KERIError::ValidationError(format!(
                "Invalid cuts = {:?}, has duplicates for evt = {:?}",
                cuts,
                serder.ked()
            )));
        }

        // Validate that all cuts are in current witness set
        if !cut_set.is_subset(&wit_set) {
            return Err(KERIError::ValidationError(format!(
                "Invalid cuts = {:?}, not all members in wits for evt = {:?}",
                cuts,
                serder.ked()
            )));
        }

        // Extract adds from serder
        let adds = serder.adds().unwrap_or_else(|| Vec::new());

        // Validate adds: check for duplicates
        let add_set: HashSet<String> = HashSet::from_iter(adds.iter().cloned());
        if add_set.len() != adds.len() {
            return Err(KERIError::ValidationError(format!(
                "Invalid adds = {:?}, has duplicates for evt = {:?}",
                adds,
                serder.ked()
            )));
        }

        // Check that cuts and adds don't intersect
        if !cut_set.is_disjoint(&add_set) {
            return Err(KERIError::ValidationError(format!(
                "Intersecting cuts = {:?} and adds = {:?} for evt = {:?}",
                cuts,
                adds,
                serder.ked()
            )));
        }

        // Check that current witnesses and adds don't intersect
        if !wit_set.is_disjoint(&add_set) {
            return Err(KERIError::ValidationError(format!(
                "Intersecting wits = {:?} and adds = {:?} for evt = {:?}",
                wits,
                adds,
                serder.ked()
            )));
        }

        // Calculate new witness list: remove cuts, add adds
        // First remove cuts from wit_set
        let wit_set_after_cuts: HashSet<String> = wit_set.difference(&cut_set).cloned().collect();

        // Then add adds to the set after cuts
        let new_wit_set: HashSet<String> = wit_set_after_cuts.union(&add_set).cloned().collect();

        // Convert back to a vector
        let new_wits = new_wit_set.into_iter().collect::<Vec<String>>();

        // Validate that the final witness count is correct
        if new_wits.len() != (wits.len() - cuts.len() + adds.len()) {
            return Err(KERIError::ValidationError(format!(
                "Invalid member combination among wits = {:?}, cuts = {:?}, and adds = {:?} for evt = {:?}",
                wits, cuts, adds, serder.ked()
            )));
        }

        Ok((new_wits, cuts, adds))
    }

    pub fn verfers(&self) -> Option<Vec<Verfer>> {
        self.verfers.clone()
    }

    pub fn sner(&self) -> Option<Number> {
        self.sner.clone()
    }

    pub fn last_est(&self) -> Option<LastEstLoc> {
        self.last_est.clone()
    }

    fn escrow_mf_event(
        &self,
        _serder: &SerderKERI,
        _sigers: Vec<Siger>,
        _wigers: Option<Vec<Siger>>,
        _seqner: Option<&Seqner>,
        _saider: Option<&Saider>,
        _local: bool,
    ) -> Result<(), KERIError> {
        todo!("Implement escrow for misfit events")
    }

    fn escrow_ps_event(
        &self,
        _serder: &SerderKERI,
        _sigers: Vec<Siger>,
        _wigers: Option<Vec<Siger>>,
        _seqner: Option<&Seqner>,
        _saider: Option<&Saider>,
        _local: bool,
    ) -> Result<(), KERIError> {
        todo!("Implement escrow for partially signed events")
    }

    fn escrow_pw_event(
        &self,
        _serder: &SerderKERI,
        _wigers: Option<Vec<Siger>>,
        _sigers: Vec<Siger>,
        _seqner: Option<&Seqner>,
        _saider: Option<&Saider>,
        _local: bool,
    ) -> Result<bool, KERIError> {
        todo!("Implement escrow for partially witnessed events")
    }

    fn escrow_delegable_event(
        &self,
        _serder: &SerderKERI,
        _sigers: &[Siger],
        _wigers: Option<Vec<Siger>>,
        _local: bool,
    ) -> Result<(), KERIError> {
        todo!("Implement escrow for delegable events")
    }

    /// Returns a list of indices (ondices) suitable for Tholder.satisfy
    /// from self.ndigers (prior next key digests) as exposed by event sigers.
    /// Uses dual index feature of siger. Assumes that each siger.verfer is
    /// from the correct key given by siger.index and the signature has been verified.
    ///
    /// A key given by siger.verfer (at siger.index in the current key list)
    /// may expose a prior next key hidden by the diger at siger.ondex in .digers.
    ///
    /// Each returned ondex must be properly exposed by a siger in sigers
    /// such that the siger's indexed key given by siger.verfer matches the
    /// siger's ondexed digest from digers.
    ///
    /// The ondexed digest's code is used to compute the digest of the corresponding
    /// indexed key verfer to verify that they match. This supports crypto agility
    /// for different digest codes, i.e., all digests in .digers may use a different
    /// algorithm.
    ///
    /// Only ondices from properly matching key and digest are returned.
    ///
    /// # Arguments
    ///
    /// * `sigers` - Vector of Siger instances of indexed signatures with .verfer
    ///
    /// # Returns
    ///
    /// * `Result<Vec<usize>, KERIError>` - Vector of ondices that are properly exposed
    fn exposeds(&self, sigers: &[Siger]) -> Result<Vec<usize>, KERIError> {
        let mut odxs = Vec::new();

        // Get ndigers or return empty vector if not available
        let ndigers = match &self.ndigers {
            Some(digers) => digers,
            None => return Ok(odxs), // Return empty vector if no ndigers
        };

        for siger in sigers {
            // Get the ondex from the siger
            let ondex = match siger.ondex() {
                Some(ondex) => ondex as usize,
                None => continue, // Skip if ondex is None
            };

            // Try to get the corresponding diger
            if ondex >= ndigers.len() {
                continue; // Skip if ondex is out of bounds
            }
            let diger = &ndigers[ondex];

            // Get the verfer from the siger
            let verfer = match siger.verfer() {
                Some(vrf) => vrf,
                None => continue, // Skip if verfer is None
            };

            // Create a digest of the verfer using the same code as the diger
            let kdig = match Diger::new(Some(verfer.raw()), Some(diger.code()), None, None) {
                Ok(d) => d.qb64(),
                Err(_) => continue, // Skip if there's an error creating the digest
            };

            // If the digests match, add the ondex to the list
            if kdig == diger.qb64() {
                odxs.push(ondex);
            }
        }

        Ok(odxs)
    }

    fn validate_delegation(
        &self,
        _serder: &SerderKERI,
        _sigers: &[Siger],
        _wigers: Option<Vec<Siger>>,
        _wits: &[String],
        delpre: Option<&str>,
        _delseqner: Option<&Seqner>,
        _delsaider: Option<&Saider>,
        _eager: bool,
        _local: bool,
    ) -> Result<(Option<Seqner>, Option<Saider>), KERIError> {
        if delpre.is_none() {
            return Ok((None, None));
        }

        Err(KERIError::ValidationError(
            "Delegation not yet implemented for this kever".to_string(),
        ))
    }

    /// Not an inception event. Verify event serder and indexed signatures
    /// in sigers and update state
    ///
    /// # Arguments
    ///
    /// * `serder` - Instance of event
    /// * `sigers` - List of SigMat instances of indexed signatures of controller
    ///             signatures of event. Index is offset into keys list from latest
    ///             est event and when provided index is offset into key digest list
    ///             from prior next est event to latest est event.
    /// * `wigers` - Optional list of Siger instances of indexed witness signatures of
    ///             event. Index is offset into wits list from latest est event
    /// * `delseqner` - Optional instance of delegating event sequence number.
    ///                If this event is not delegated then seqner is ignored
    /// * `delsaider` - Optional instance of delegating event said.
    ///                If this event is not delegated then diger is ignored
    /// * `firner` - Optional Seqner instance of cloned first seen ordinal
    ///             If cloned mode then firner maybe provided (not None)
    ///             When firner provided then compare fn of dater and database and
    ///             first seen if not match then log and add cue notify problem
    /// * `dater` - Optional Dater instance of cloned replay datetime
    ///            If cloned mode then dater maybe provided (not None)
    ///            When dater provided then use dater for first seen datetime
    /// * `eager` - If true, try harder to find validate events by walking KELs.
    ///            Enables only being eager in escrow processing not initial parsing.
    ///            If false, only use pre-existing information if any.
    /// * `local` - Event source for validation logic.
    ///            True means event source is local (protected).
    ///            False means event source is remote (unprotected).
    /// * `check` - If true, do not update the database in any non-idempotent way.
    ///            Useful for reinitializing the Kevers from a persisted KEL without
    ///            updating non-idempotent first seen .fels and timestamps.
    ///
    /// # Returns
    ///
    /// * `Result<(), KERIError>` - Ok if successful, Error otherwise
    pub fn update(
        &mut self,
        serder: SerderKERI,
        sigers: Vec<Siger>,
        wigers: Option<Vec<Siger>>,
        delseqner: Option<Seqner>,
        delsaider: Option<Saider>,
        firner: Option<Seqner>,
        dater: Option<Dater>,
        eager: bool,
        local: bool,
        check: bool,
    ) -> Result<(), KERIError> {
        let ked = &serder.ked();

        // Check if identifier is transferable
        if !self.transferable() {
            return Err(KERIError::ValidationError(
                "Can't rotate; Prefixer is either missing or identifier is non-transferrable"
                    .to_string(),
            ));
        }

        // Check if event prefix matches kever prefixer
        if serder.pre() != Some(self.prefixer.clone().unwrap().qb64()) {
            return Err(KERIError::ValidationError(format!(
                "Mismatch event aid prefix = {} expecting = {} for evt = {:?}",
                serder.pre().unwrap(),
                self.prefixer.as_ref().unwrap().qb64(),
                ked
            )));
        }

        let local = local; // No conversion needed, bool is already bool

        let sner = serder.sn().unwrap_or_default(); // Get sequence number from serder
        let ilk = serder.ilk().unwrap();

        // Handle rotation or delegated rotation event
        if ilk == Ilk::Rot || ilk == Ilk::Drt {
            // Check if trying to do non-delegated rotation on delegated prefix
            if self.delegated && ilk != Ilk::Drt {
                return Err(KERIError::ValidationError(format!(
                    "Attempted non delegated rotation on delegated pre = {} with evt = {:?}",
                    serder.pre().unwrap(),
                    ked
                )));
            }

            // Validate rotation
            let (tholder, toader, wits, cuts, adds) = self.rotate(&serder)?;

            // Validate signatures, delegation if any, and witnessing when applicable
            let (sigers_verified, wigers_verified, _, delseqner_updated, delsaider_updated) = self
                .val_sigs_wigs_del(
                    serder.clone(),
                    sigers,
                    serder.verfers(),
                    tholder.clone(),
                    wigers,
                    Some(toader.clone()),
                    wits.clone(),
                    delseqner,
                    delsaider,
                    eager,
                    local,
                )?;

            // Log event to KEL and FEL if not in check mode
            let (fn_val, dts) = self.log_event(
                serder.clone(),
                sigers_verified,
                wigers_verified,
                Some(wits.clone()),
                !check, // first
                delseqner_updated,
                delsaider_updated,
                firner,
                dater,
                local,
            )?;

            // Update state
            self.sner = Some(Number::from_num(&BigUint::from(sner))?);
            self.serder = Some(serder.clone());
            self.ilk = ilk; // Default to Rot if unknown
            self.tholder = Some(tholder);
            self.verfers = serder.verfers();
            self.ndigers = serder.ndigers();
            self.ntholder = serder.ntholder();
            self.toader = Some(toader);
            self.wits = Some(wits);
            self.cuts = Some(cuts);
            self.adds = Some(adds);

            // Last establishment event location needed to recognize recovery events
            self.last_est = Some(LastEstLoc {
                s: sner,
                d: serder.said().unwrap().to_string(),
            });

            // Update first seen number and date if not in check mode
            if let Some(fn_num) = fn_val {
                self.fner = Some(Number::from_num(&BigUint::from(fn_num))?);
                self.dater = Some(Dater::from_dt(dts));
                // Update state in database
                if let Some(prefixer) = &self.prefixer {
                    self.db.states.pin(&[&prefixer.qb64()], &self.state()?)?;
                }
            }
        }
        // Handle interaction event
        else if ilk == Ilk::Ixn {
            // Check if est_only is true
            if self.est_only.unwrap_or(false) {
                return Err(KERIError::ValidationError(format!(
                    "Unexpected non-establishment event = {:?}",
                    serder.ked()
                )));
            }

            // Check sequence number
            let self_sn = self.sner.as_ref().map(|n| n.num()).unwrap_or(0);
            if sner != (self_sn + 1) as u64 {
                return Err(KERIError::ValidationError(format!(
                    "Invalid sn = {} expecting = {} for evt = {:?}",
                    sner,
                    self_sn + 1,
                    ked
                )));
            }

            // Check prior event digest
            let self_said = self.serder.as_ref().map(|s| s.said()).unwrap_or_default();
            if ked["p"] != SadValue::String(self_said.unwrap_or_default().to_string()) {
                return Err(KERIError::ValidationError(format!(
                    "Mismatch event dig = {} with state dig = {} for evt = {:?}",
                    ked["p"].as_str().unwrap(),
                    self_said.unwrap(),
                    ked
                )));
            }

            // Use keys, sith, toad, and wits from pre-existing Kever state
            let verfers = self.verfers.clone().ok_or_else(|| {
                KERIError::ValidationError("Missing verfers in Kever state".to_string())
            })?;

            let tholder = self.tholder.clone().ok_or_else(|| {
                KERIError::ValidationError("Missing tholder in Kever state".to_string())
            })?;

            let toader = self.toader.clone().ok_or_else(|| {
                KERIError::ValidationError("Missing toader in Kever state".to_string())
            })?;

            let wits = self.wits.clone().unwrap_or_default();

            // Validate signatures, delegation, and witnessing
            let (sigers_verified, wigers_verified, _, _, _) = self.val_sigs_wigs_del(
                serder.clone(),
                sigers,
                Some(verfers),
                tholder,
                wigers,
                Some(toader),
                wits,
                None, // No delegation for ixn events
                None, // No delegation for ixn events
                eager,
                local,
            )?;

            // Log event to KEL and FEL if not in check mode
            let (fn_val, dts) = self.log_event(
                serder.clone(),
                sigers_verified,
                wigers_verified,
                None,   // No wits param for ixn
                !check, // first
                None,   // No delegation for ixn
                None,   // No delegation for ixn
                None,   // No firner for standard ixn
                None,   // No dater for standard ixn
                local,
            )?;

            // Update state
            self.sner = Some(Number::from_num(&BigUint::from(sner))?);
            self.serder = Some(serder);
            self.ilk = ilk;

            // Update first seen number and date if not in check mode
            if let Some(fn_num) = fn_val {
                self.fner = Some(Number::from_num(&BigUint::from(fn_num))?);
                self.dater = Some(Dater::from_dt(dts));
                // Update state in database
                if let Some(prefixer) = &self.prefixer {
                    self.db.states.pin(&[&prefixer.qb64()], &self.state()?)?;
                }
            }
        }
        // Handle unsupported event type
        else {
            return Err(KERIError::ValidationError(format!(
                "Unsupported ilk = {} for evt = {:?}",
                ilk, ked
            )));
        }

        Ok(())
    }

    /// Generic Rotate Operation Validation Processing
    /// Validates provisional rotation
    /// Same logic for both 'rot' and 'drt' (plain and delegated rotation)
    ///
    /// # Arguments
    ///
    /// * `serder` - Instance of rotation ('rot' or 'drt') event.
    ///
    /// # Returns
    ///
    /// A tuple (tholder, toader, wits, cuts, adds) of provisional results
    /// of rotation subject to additional validation
    ///
    /// # Errors
    ///
    /// * `ValidationError` - if the rotation event is invalid
    /// * `ValueError` - if the toad value is invalid
    pub fn rotate(
        &self,
        serder: &SerderKERI,
    ) -> Result<(Tholder, Number, Vec<String>, Vec<String>, Vec<String>), KERIError> {
        let ked = &serder.ked();
        let sn = serder.sn().unwrap_or_default();
        let pre = serder.pre().unwrap();
        let prior = serder.prior().unwrap();
        let ilk = serder.ilk().unwrap();

        // Get current sequence number from self
        let self_sn = self.sner.as_ref().map(|n| n.num()).unwrap_or(0);

        // Check if the event i3s out of order
        if sn > (self_sn + 1) as u64 {
            return Err(KERIError::ValidationError(format!(
                "Out of order event sn = {} expecting = {} for evt = {:?}",
                sn,
                self_sn + 1,
                ked
            )));
        } else if sn <= self_sn as u64 {
            // Event is stale or recovery
            let last_est_sn = self.last_est.as_ref().map(|l| l.s).unwrap_or(0);

            if (ilk == Ilk::Rot && sn <= last_est_sn) || (ilk == Ilk::Drt && sn < last_est_sn) {
                // Stale event
                return Err(KERIError::ValidationError(format!(
                    "Stale event sn = {} expecting = {} for evt = {:?}",
                    sn,
                    self_sn + 1,
                    ked
                )));
            } else {
                // Recovery event
                if ilk == Ilk::Rot && self.ilk != Ilk::Ixn {
                    // Recovery may only override ixn state
                    return Err(KERIError::ValidationError(format!(
                        "Invalid recovery attempt: Recovery at ilk = {} not ilk = {} for evt = {:?}",
                        self.ilk, Ilk::Ixn, ked
                    )));
                }

                // Use sn of prior event to fetch prior event
                let psn = sn - 1;

                // Fetch raw serialization of last inserted event at psn
                let key = sn_key(pre.clone(), psn);
                let pdig = match self.db.kels.get_last(&[&key])? {
                    Some(dig) => match String::from_utf8(dig) {
                        Ok(d) => d,
                        Err(_) => return Err(KERIError::ValueError("Invalid digest".to_string())),
                    },
                    None => {
                        return Err(KERIError::ValidationError(format!(
                            "Invalid recovery attempt: Bad sn = {} for event = {:?}",
                            psn, ked
                        )))
                    }
                };

                // Get the event from database
                let dig_key = dg_key(pre, pdig.clone());
                let praw = match self.db.evts.get::<_, Vec<u8>>(&[&dig_key])? {
                    Some(raw) => raw,
                    None => {
                        return Err(KERIError::ValidationError(format!(
                            "Invalid recovery attempt: Bad dig = {}",
                            pdig
                        )))
                    }
                };

                // Deserialize prior event
                let pserder = SerderKERI::from_raw(&praw, None)
                    .map_err(|e| KERIError::ValueError(format!("Invalid prior event: {}", e)))?;

                // Compare prior said with retrieved event said
                if prior != pserder.said().unwrap_or_default() {
                    return Err(KERIError::ValidationError(format!(
                        "Invalid recovery attempt: Mismatch recovery event prior dig = {} with dig = {:?} of event sn = {} evt = {:?}",
                        prior, pserder.said(), psn, ked
                    )));
                }
            }
        } else {
            // New non-recovery event (sn == self_sn + 1)
            // Check if prior event dig matches current event said
            let self_said = self.serder.as_ref().map(|s| s.said()).unwrap_or_default();
            if prior != self_said.unwrap_or_default() {
                return Err(KERIError::ValidationError(format!(
                    "Mismatch event dig = {} with state dig = {:?} for evt = {:?}",
                    prior, self_said, ked
                )));
            }
        }

        // Check if rotation is allowed (non-transferable check)
        if self.ndigers.is_none() || self.ndigers.as_ref().map_or(true, |d| d.is_empty()) {
            return Err(KERIError::ValidationError(format!(
                "Attempted rotation for nontransferable prefix = {} for evt = {:?}",
                self.prefixer.as_ref().map(|p| p.qb64()).unwrap_or_default(),
                ked
            )));
        }

        // Parse threshold and keys
        let tholder = serder.tholder().unwrap_or_default();
        let keys = serder.keys().unwrap_or_default();

        // Check if keys are sufficient for threshold
        if keys.len() < tholder.size() {
            return Err(KERIError::ValidationError(format!(
                "Invalid sith = {} for keys = {:?} for evt = {:?}",
                tholder.sith(),
                keys,
                ked
            )));
        }

        // Compute witnesses from existing wits with new cuts and adds from event
        let (wits, cuts, adds) = self.derive_backs(serder)?;

        // Get witness threshold from event
        let toader = serder.bner().unwrap_or_default();

        // Validate witness threshold
        if !wits.is_empty() {
            if toader.num() < 1 || toader.num() > wits.len() as u128 {
                return Err(KERIError::ValueError(format!(
                    "Invalid toad = {} for backers (wits)={:?} for event={:?}",
                    toader.num(),
                    wits,
                    ked
                )));
            }
        } else {
            if toader.num() != 0 {
                return Err(KERIError::ValueError(format!(
                    "Invalid toad = {} for backers (wits)={:?} for event={:?}",
                    toader.num(),
                    wits,
                    ked
                )));
            }
        }

        Ok((tholder, toader, wits, cuts, adds))
    }

    pub fn log_event(
        &self,
        serder: SerderKERI,
        sigers: Vec<Siger>,
        wigers: Option<Vec<Siger>>,
        wits: Option<Vec<String>>,
        first: bool,
        seqner: Option<Seqner>,
        saider: Option<Saider>,
        _firner: Option<Seqner>,
        dater: Option<Dater>,
        local: bool,
    ) -> Result<(Option<u64>, chrono::DateTime<chrono::Utc>), KERIError> {
        // Default values
        let local = if local { true } else { false };
        let mut fn_num: Option<u64> = None; // None means not a first seen log event

        // Create digest key for the event
        let dg_keys = vec![serder.pre().unwrap(), serder.said().unwrap().to_string()]; // For esrs database

        // Get current timestamp in ISO 8601 format
        let now = chrono::Utc::now();
        let dts_b = now.to_rfc3339().into_bytes();

        // Put datetime stamp (idempotent, won't change if already exists)
        self.db.dtss.add(&dg_keys, &dts_b)?;

        // Store signatures if provided
        if !sigers.is_empty() {
            for siger in sigers.iter() {
                self.db
                    .sigs
                    .add(&dg_keys, &siger.qb64().into_bytes().as_slice())?;
            }
        }

        // Store witness signatures if provided
        if let Some(wigers) = &wigers {
            for wiger in wigers.iter() {
                self.db
                    .sigs
                    .add(&dg_keys, &wiger.qb64().into_bytes().as_slice())?;
            }
        }

        // Store witnesses if provided
        if let Some(wits) = &wits {
            if !wits.is_empty() {
                for wit in wits {
                    self.db
                        .wits
                        .add(&dg_keys, &wit.clone().into_bytes().as_slice())?;
                }
            }
        }

        // Store serialized event (idempotent, may already be escrowed)
        self.db.evts.put(&dg_keys, &serder.raw())?;

        // Handle delegation for authorized delegated or issued event
        if self.delpre.is_some()
            && serder.ilk() != Some(Ilk::Ixn)
            && !self.locally_owned(None)
            && !self.locally_witnessed(Some(wits.as_deref().unwrap_or(&[])), None)
            && seqner.is_some()
            && saider.is_some()
        {
            // Create authorizer (delegator/issuer) event seal couple
            let seqner = seqner.unwrap();
            let saider = saider.unwrap();
            let couple = [seqner.qb64().as_bytes(), saider.qb64().as_bytes()].concat();
            self.db.aess.put(&dg_keys, &couple)?;
        }

        // Update event source record
        let _esr = match self.db.esrs.get(&dg_keys) {
            Ok(Some(mut esr)) => {
                // If local and existing record is remote, update to local
                if local && !esr.local {
                    esr.local = local;
                    self.db.esrs.pin(&dg_keys, &esr)?;
                }
                esr
            }
            _ => {
                // Not preexisting, create and store new record
                let esr = EventSourceRecord::with_local(local);
                self.db.esrs.put(&dg_keys, &esr)?;
                esr
            }
        };

        // Handle first seen events
        if first {
            // Append event digest to first seen database in order
            match self
                .db
                .fels
                .append_on(&[&serder.preb().unwrap()], &serder.saidb().unwrap())
            {
                Ok(fn_val) => {
                    fn_num = Some(fn_val);

                    // Use original timestamp from dater for cloned replay
                    let dts_to_set = match &dater {
                        Some(d) => d.dtsb(),
                        None => dts_b.clone(),
                    };

                    // Set first seen timestamp
                    self.db.dtss.pin(&dg_keys, &[&dts_to_set])?;

                    // Store first seen ordinal number
                    let fn_seqner = Number::from_num(&BigUint::from(fn_val))?;
                    self.db.fons.pin(&dg_keys, &fn_seqner)?;
                }
                Err(e) => {
                    return Err(KERIError::DatabaseError(format!(
                        "Failed to append to FEL: {}",
                        e
                    )))
                }
            }
        }

        // Add event to Key Event Log
        println!("SEQUENCE NUMBER: {:?}", serder.sn().unwrap());
        let sn_key = sn_key(serder.preb().unwrap(), serder.sn().unwrap());
        self.db.kels.add(&[sn_key], &serder.saidb().unwrap())?;

        // Return first seen number (if any) and timestamp
        Ok((fn_num, now))
    }

    /// Returns KeyStateRecord instance of current key state
    pub fn state(&self) -> Result<KeyStateRecord, KERIError> {
        // Ensure required fields are available
        let prefixer = self
            .prefixer()
            .ok_or_else(|| KERIError::ValueError("Missing prefixer in Kever state".to_string()))?;

        let tholder = self
            .tholder()
            .ok_or_else(|| KERIError::ValueError("Missing tholder in Kever state".to_string()))?;

        let serder = self
            .serder
            .as_ref()
            .ok_or_else(|| KERIError::ValueError("Missing serder in Kever state".to_string()))?;

        let sner = self
            .sner
            .as_ref()
            .ok_or_else(|| KERIError::ValueError("Missing sner in Kever state".to_string()))?;

        let fner = self
            .fner
            .as_ref()
            .ok_or_else(|| KERIError::ValueError("Missing fner in Kever state".to_string()))?;

        let dater = self
            .dater
            .as_ref()
            .ok_or_else(|| KERIError::ValueError("Missing dater in Kever state".to_string()))?;

        let verfers = self
            .verfers
            .as_ref()
            .ok_or_else(|| KERIError::ValueError("Missing verfers in Kever state".to_string()))?;

        let toader = self
            .toader()
            .ok_or_else(|| KERIError::ValueError("Missing toader in Kever state".to_string()))?;

        let last_est = self
            .last_est
            .as_ref()
            .ok_or_else(|| KERIError::ValueError("Missing last_est in Kever state".to_string()))?;

        // Create StateEstEvent
        let eevt = StateEERecord {
            s: format!("{:x}", last_est.s),
            d: last_est.d.clone(),
            br: self.cuts.clone(),
            ba: self.adds.clone(),
        };

        // Create configuration traits
        let mut cnfg = Vec::new();
        if self.est_only.unwrap_or(false) {
            cnfg.push(trait_dex::EST_ONLY.to_string());
        }
        if self.do_not_delegate.unwrap_or(false) {
            cnfg.push(trait_dex::DO_NOT_DELEGATE.to_string());
        }

        // Collect signing keys
        let keys: Vec<String> = verfers.iter().map(|verfer| verfer.qb64()).collect();

        // Get next key digests
        let ndigs = match &self.ndigers {
            Some(digers) => digers.iter().map(|diger| diger.qb64()).collect(),
            None => Vec::new(),
        };

        // Get witnesses
        let wits = self.wits().clone();

        // Get prior event digest and handle None case
        let pig = serder.prior().clone().unwrap_or_default();

        // Use StateEventBuilder to create the state record
        let state_builder = StateEventBuilder::new(
            prefixer.qb64(),                    // pre
            sner.num() as u64,                  // sn
            pig,                                // pig
            serder.said().unwrap().to_string(), // dig
            fner.num() as u64,                  // fn_
            self.ilk.to_string(),               // eilk
            keys,                               // keys
            eevt,                               // eevt
        )
        .with_stamp(dater.dts()) // stamp
        .with_sith(tholder.sith()) // sith
        .with_ndigs(ndigs) // ndigs
        .with_toad(toader.num() as usize) // toad
        .with_wits(wits) // wits
        .with_cnfg(cnfg); // cnfg

        // Add next threshold if available
        let state_builder = match &self.ntholder {
            Some(ntholder) => state_builder.with_nsith(ntholder.sith()),
            None => state_builder,
        };

        // Add delegator prefix if available
        let state_builder = match &self.delpre {
            Some(delpre) => state_builder.with_dpre(delpre.clone()),
            None => state_builder,
        };

        // Build the state record
        let state_record = state_builder
            .build()
            .map_err(|e| KERIError::ValueError(e.to_string()))?;

        Ok(state_record)
    }

    fn tholder(&self) -> Option<Tholder> {
        self.tholder.clone()
    }

    pub fn toader(&self) -> Option<Number> {
        self.toader.clone()
    }

    fn wits(&self) -> Vec<String> {
        self.wits.clone().unwrap_or_else(Vec::new)
    }

    pub fn prefixer(&self) -> Option<Prefixer> {
        self.prefixer.clone()
    }

    pub fn serder(&self) -> Option<SerderKERI> {
        self.serder.clone()
    }

    pub fn delpre(&self) -> Option<String> {
        self.delpre.clone()
    }

    fn ndigs(&self) -> Vec<String> {
        if self.ndigers.is_none() {
            Vec::new()
        } else {
            self.ndigers
                .clone()
                .unwrap()
                .iter()
                .map(|d| d.qb64())
                .collect()
        }
    }

    /// Returns either the most recent prior list of digers before .last_est or None
    ///
    /// Starts searching at sn or if sn is None at sn = .last_est.s - 1
    ///
    /// Returns list of Digers instances at the most recent prior est event relative
    /// to the given sequence number (sn) otherwise returns None.
    /// Walks backwards to the more recent prior establishment event before the
    /// .sn if any.
    /// If sn represents an interaction event (ixn) then the result will be the
    /// current valid list of digers. If sn represents an establishment event then
    /// the result will be the list of digers immediately prior to the current list.
    ///
    /// # Arguments
    ///
    /// * `sn` - Optional sequence number to start searching. If None then start at .last_est.s - 1
    ///
    /// # Returns
    ///
    /// * `Result<Option<Vec<Diger>>, KERIError>` - Vector of Diger instances or None if no prior est evt
    ///    to current .last_est
    pub fn fetch_prior_digers(&self, sn: Option<u64>) -> Result<Option<Vec<Diger>>, KERIError> {
        // Get the prefix from the prefixer
        let pre = match &self.prefixer {
            Some(prefixer) => prefixer.qb64(),
            None => return Err(KERIError::ValidationError("Missing prefixer".to_string())),
        };

        // Determine the starting sequence number
        let start_sn = match sn {
            Some(s) => s,
            None => match &self.last_est {
                Some(last_est) => {
                    if last_est.s > 0 {
                        last_est.s - 1
                    } else {
                        return Ok(None);
                    }
                }
                None => return Ok(None),
            },
        };

        // Iterate backwards through the KEL from the starting sequence number
        let kel_back_iter = self
            .db
            .kels
            .get_on_back_iter::<_, Vec<u8>>(&[&pre], start_sn as u32)?;

        for digb in kel_back_iter {
            // Create the digest key for the event
            let dgkey = dg_key(&pre, &digb?);

            // Get the event data
            let raw = match self.db.evts.get::<_, Vec<u8>>(&[dgkey]) {
                Ok(evt) => evt,
                Err(_) => return Ok(None),
            };

            // Parse the event
            let serder = SerderKERI::from_raw(&Vec::from(raw.unwrap()), None)?;

            // Check if this is an establishment event
            if serder.estive() {
                // Return the next digests from this event
                return Ok(serder.ndigers());
            }
        }

        // No prior establishment event found
        Ok(None)
    }

    pub fn transferable(&self) -> bool {
        match &self.prefixer {
            Some(prefixer) => {
                self.ndigers.is_some()
                    && self.ndigers.clone().unwrap().len() > 0
                    && prefixer.transferable()
            }
            None => false,
        }
    }
}

/// KeverBuilder provides a builder pattern for constructing a Kever instance
/// Each optional parameter of Kever::new is represented by a with_* method
pub struct KeverBuilder<'db> {
    db: Arc<&'db Baser<'db>>,
    state: Option<KeyStateRecord>,
    serder: Option<SerderKERI>,
    sigers: Option<Vec<Siger>>,
    wigers: Option<Vec<Siger>>,
    est_only: Option<bool>,
    delseqner: Option<Seqner>,
    delsaider: Option<Saider>,
    firner: Option<Seqner>,
    dater: Option<Dater>,
    eager: Option<bool>,
    local: Option<bool>,
    check: Option<bool>,
}

impl<'db> KeverBuilder<'db> {
    /// Create a new KeverBuilder with required database
    pub fn new(db: Arc<&'db Baser<'db>>) -> Self {
        KeverBuilder {
            db,
            state: None,
            serder: None,
            sigers: None,
            wigers: None,
            est_only: None,
            delseqner: None,
            delsaider: None,
            firner: None,
            dater: None,
            eager: None,
            local: None,
            check: None,
        }
    }

    /// Set the key state record
    pub fn with_state(mut self, state: KeyStateRecord) -> Self {
        self.state = Some(state);
        self
    }

    /// Set the serialized event data
    pub fn with_serder(mut self, serder: SerderKERI) -> Self {
        self.serder = Some(serder);
        self
    }

    /// Set the list of indexed controller signatures
    pub fn with_sigers(mut self, sigers: Vec<Siger>) -> Self {
        self.sigers = Some(sigers);
        self
    }

    /// Set the list of indexed witness signatures
    pub fn with_wigers(mut self, wigers: Vec<Siger>) -> Self {
        self.wigers = Some(wigers);
        self
    }

    /// Set the establishment only events flag
    pub fn with_est_only(mut self, est_only: bool) -> Self {
        self.est_only = Some(est_only);
        self
    }

    /// Set the delegating event sequence number
    pub fn with_delseqner(mut self, delseqner: Seqner) -> Self {
        self.delseqner = Some(delseqner);
        self
    }

    /// Set the delegating event SAID
    pub fn with_delsaider(mut self, delsaider: Saider) -> Self {
        self.delsaider = Some(delsaider);
        self
    }

    /// Set the first seen ordinal number
    pub fn with_firner(mut self, firner: Seqner) -> Self {
        self.firner = Some(firner);
        self
    }

    /// Set the first seen timestamp
    pub fn with_dater(mut self, dater: Dater) -> Self {
        self.dater = Some(dater);
        self
    }

    /// Set the eager validation flag
    pub fn with_eager(mut self, eager: bool) -> Self {
        self.eager = Some(eager);
        self
    }

    /// Set the local flag for event source validation logic
    pub fn with_local(mut self, local: bool) -> Self {
        self.local = Some(local);
        self
    }

    /// Set the check flag for database update control
    pub fn with_check(mut self, check: bool) -> Self {
        self.check = Some(check);
        self
    }

    /// Build the Kever instance
    pub fn build(self) -> Result<Kever<'db>, KERIError> {
        Kever::new(
            self.db,
            self.state,
            self.serder,
            self.sigers,
            self.wigers,
            self.est_only,
            self.delseqner,
            self.delsaider,
            self.firner,
            self.dater,
            self.eager,
            self.local,
            self.check,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cesr::diger::Diger;
    use crate::cesr::signing::{Salter, Sigmat};
    use crate::cesr::tholder::TholderThold;
    use crate::cesr::{mtr_dex, pre_dex};
    use crate::keri::core::eventing::interact::InteractEventBuilder;
    use crate::keri::core::eventing::rotate::RotateEventBuilder;
    use crate::keri::core::eventing::InceptionEventBuilder;
    use crate::keri::core::serdering::SadValue;
    use crate::keri::db::dbing::LMDBer;
    use crate::keri::KERIError;
    use std::collections::HashMap;
    use std::sync::Arc;

    #[test]
    fn test_kever() -> Result<(), KERIError> {
        Ok(())
    }

    #[test]
    fn test_kever_builder() -> Result<(), KERIError> {
        // This test would need proper test fixtures to be meaningful
        // Just showing example usage
        let lmdber = LMDBer::builder()
            .name("temp")
            .reopen(true)
            .build()
            .expect("Failed to open Baser database: {}");
        let db = Baser::new(Arc::new(&lmdber)).expect("Failed to create manager database");

        let raw = [
            0x05, 0xaa, 0x8f, 0x2d, 0x53, 0x9a, 0xe9, 0xfa, 0x55, 0x9c, 0x02, 0x9c, 0x9b, 0x08,
            0x48, 0x75,
        ];
        let salter = Salter::new(Some(&raw), None, None)?;

        // Create current key (one signer)
        let sith = 1;
        let skp0 = salter.signer(None, Some(true), "A", None, true)?;
        assert_eq!(skp0.code(), mtr_dex::ED25519_SEED);
        assert_eq!(skp0.verfer().code(), mtr_dex::ED25519);
        assert_eq!(
            skp0.verfer().qb64(),
            "DAUDqkmn-hqlQKD8W-FAEa5JUvJC2I9yarEem-AAEg3e"
        );
        let keys = vec![skp0.verfer().qb64()];

        // Create next key (transferable by default)
        let skp1 = salter.signer(None, Some(true), "N", None, true)?;
        assert_eq!(skp1.code(), mtr_dex::ED25519_SEED);
        assert_eq!(skp1.verfer().code(), mtr_dex::ED25519);

        // Compute next digest
        let ndiger = Diger::from_ser(skp1.verfer().qb64b().as_slice(), None)?;
        let nxt = vec![ndiger.qb64()];
        assert_eq!(nxt, vec!["EAKUR-LmLHWMwXTLWQ1QjxHrihBmwwrV2tYaSG7hOrWj"]);

        // Set up initial values
        let sn = 0; // Inception event
        let toad = 0; // No witnesses
        let nsigs = 1; // One attached signature

        // Creating the event serialization with non-digestive prefix
        let mut saids = HashMap::new();
        saids.insert("i", pre_dex::ED25519.to_string());

        let mut serder = SerderKERI::new(
            None,           // raw
            None,           // sad
            Some(true),     // makify
            None,           //smellage
            None,           // proto
            None,           // version
            None,           // kind
            Some(Ilk::Icp), // ilk
            Some(saids),    // saids
        )?;

        // Get sad and modify it
        let mut sad = serder.sad();

        // Update sad with required fields
        sad.insert("i".to_string(), SadValue::from_string(skp0.verfer().qb64()));
        sad.insert("s".to_string(), SadValue::from_string(format!("{:x}", sn)));
        sad.insert(
            "kt".to_string(),
            SadValue::from_string(format!("{:x}", sith)),
        );
        sad.insert(
            "k".to_string(),
            SadValue::from_array(
                keys.iter()
                    .map(|k| SadValue::from_string(k.clone()))
                    .collect::<Vec<_>>(),
            ),
        );
        sad.insert("nt".to_string(), SadValue::from_u64(1));
        sad.insert(
            "n".to_string(),
            SadValue::from_array(
                nxt.iter()
                    .map(|n| SadValue::from_string(n.clone()))
                    .collect::<Vec<_>>(),
            ),
        );
        sad.insert(
            "bt".to_string(),
            SadValue::from_string(format!("{:x}", toad)),
        );

        // Create new serder with the updated sad and verify it
        let mut saids_for_verification = HashMap::new();
        saids_for_verification.insert("i", pre_dex::ED25519.to_string());

        serder = SerderKERI::new(
            None,
            Some(&sad),
            Some(true),
            None,
            None,
            None,
            None,
            None,
            Some(saids_for_verification),
        )?; // sad with updates

        // Verify the said and pre values
        assert_eq!(
            serder.said().unwrap(),
            "EBTCANzIfUThxmM1z1SFxQuwooGdF4QwtotRS01vZGqi"
        );
        assert_eq!(
            serder.pre().unwrap(),
            "DAUDqkmn-hqlQKD8W-FAEa5JUvJC2I9yarEem-AAEg3e"
        );
        let aid0 = serder.pre().unwrap();

        // Assign first serialization
        let tser0 = serder.clone();

        // Sign serialization
        let tsig0 = skp0.sign(tser0.raw(), Some(0), None, None)?;

        // Get the siger from the signature result
        let tsig0 = match tsig0 {
            Sigmat::Indexed(siger) => siger,
            _ => {
                return Err(KERIError::ValueError(
                    "Expected indexed signature".to_string(),
                ))
            }
        };

        // Verify signature
        assert!(skp0.verfer().verify(tsig0.raw(), tser0.raw())?);

        // Create the Kever
        let kever = KeverBuilder::new(Arc::new(&db))
            .with_serder(tser0.clone())
            .with_sigers(vec![tsig0])
            .build()?;

        // Verify Kever properties
        assert_eq!(kever.prefixer().unwrap().qb64(), aid0);

        // These assertions would need proper implementation
        assert_eq!(kever.sner.clone().unwrap().num(), 0);
        assert_eq!(
            kever
                .verfers
                .clone()
                .unwrap()
                .iter()
                .map(|v| v.qb64())
                .collect::<Vec<_>>(),
            vec![skp0.verfer().qb64()]
        );
        assert_eq!(kever.ndigs().clone(), nxt);
        let prefixer = kever
            .prefixer()
            .ok_or_else(|| KERIError::ValueError("Missing prefixer in Kever".to_string()))?;

        // Test getting state from the database
        let state: KeyStateRecord = kever
            .db
            .states
            .get(&[&prefixer.qb64()])
            .expect("State not found")
            .unwrap();

        // Get the sequence number from kever
        let sner = kever
            .sner
            .as_ref()
            .ok_or_else(|| KERIError::ValueError("Missing sner in Kever".to_string()))?;

        // Format sner.num as hex string for comparison
        let sner_hex = format!("{:x}", sner.num());

        // Test that state's sequence number matches kever's
        assert_eq!(state.s, sner_hex);
        assert_eq!(state.s, "0"); // Assert sequence is 0

        // Get the serder from kever
        let serder = kever
            .serder
            .as_ref()
            .ok_or_else(|| KERIError::ValueError("Missing serder in Kever".to_string()))?;

        // Test getting feqner (first seen ordinal) from db
        let feqner: Number = kever
            .db
            .fons
            .get(&[&prefixer.qb64(), &serder.said().unwrap().to_string()])?
            .unwrap();

        // Compare feqner's sequence number with kever's
        assert_eq!(feqner.num(), kever.sner.as_ref().unwrap().num());

        // Get state record from kever
        let ksr = kever.state()?;

        // Test that state from db matches state from kever.state()
        assert_eq!(ksr, state);

        // Test that identifier prefix matches
        assert_eq!(ksr.i, prefixer.qb64());

        // Test that sequence number matches
        assert_eq!(ksr.s, sner_hex);

        // Get verfers from kever
        let verfers = kever
            .verfers
            .as_ref()
            .ok_or_else(|| KERIError::ValueError("Missing verfers in Kever".to_string()))?;

        // Extract keys from state record
        let state_keys = ksr.k;

        // Extract qb64 keys from verfers
        let verfer_keys: Vec<String> = verfers.iter().map(|verfer| verfer.qb64()).collect();

        // Compare keys from state with keys from verfers
        assert_eq!(state_keys, verfer_keys);
        Ok(())
    }

    #[test]
    fn test_kever_missing_args() -> Result<(), KERIError> {
        // Test creating a Kever without required arguments should fail
        // This would need a proper database implementation for testing
        let lmdber = LMDBer::builder()
            .name("temp")
            .reopen(true)
            .build()
            .expect("Failed to open Baser database: {}");
        let db = Baser::new(Arc::new(&lmdber)).expect("Failed to create manager database");

        let result = KeverBuilder::new(Arc::new(&db)).build();

        assert!(result.is_err());
        match result {
            Err(KERIError::ValueError(msg)) => {
                assert!(msg.contains("Missing required arguments"));
                Ok(())
            }
            _ => Err(KERIError::ValueError(
                "Expected ValueError for missing arguments".to_string(),
            )),
        }
    }

    #[test]
    fn test_keyeventsequence_0() -> Result<(), KERIError> {
        // Test generation of a sequence of key events

        // Create salt and signers
        let salt = b"g\x15\x89\x1a@\xa4\xa47\x07\xb9Q\xb8\x18\xcdJW";
        let salter = Salter::new(Some(salt), None, None)?;
        let signers = salter.signers(8, 0, "", None, None, None, false)?;

        // Extract public keys
        let pubkeys: Vec<String> = signers.iter().map(|s| s.verfer().qb64()).collect();

        // Assert public keys match expected values
        assert_eq!(
            pubkeys,
            vec![
                "DErocgXD2RGSyvn3MObcx59jeOsEQhv2TqHirVkzrp0Q".to_string(),
                "DFXLiTjiRdSBPLL6hLa0rskIxk3dh4XwJLfctkJFLRSS".to_string(),
                "DE9YgIQVgpLwocTVrG8tidKScsQSMWwLWywNC48fhq4f".to_string(),
                "DCjxOXniUc5EUzDqERlXdptfKPHy6jNo_ZGsS4Vd8fAE".to_string(),
                "DNZHARO4dCJlluv0qezEMRmErIWWc-lzOzolBOQ15tHV".to_string(),
                "DOCQ4KN1jUlKbfjRteDYt9fxgpq1NK9_MqO5IA7shpED".to_string(),
                "DFY1nGjV9oApBzo5Oq5JqjwQsZEQqsCCftzo3WJjMMX-".to_string(),
                "DE9ZxA3qXegkgDAhOzWP45S3Ruv5ilJSkv5lvthyWNYY".to_string(),
            ]
        );

        let lmdber = LMDBer::builder()
            .name("temp")
            .reopen(true)
            .build()
            .expect("Failed to open Baser database: {}");
        let db = Baser::new(Arc::new(&lmdber)).expect("Failed to create manager database");

        // List to store event digests
        let mut event_digs = Vec::new();

        // Event 0 - Inception Transferable (nxt digest not empty)
        let keys0 = vec![signers[0].verfer().qb64()];

        // Compute nxt digest from keys1
        let keys1 = vec![signers[1].verfer().qb64()];
        let ndiger1 = Diger::from_ser(&signers[1].verfer().qb64b(), None)?;
        let nxt1 = vec![ndiger1.qb64()];

        // Verify next digest matches expected value
        assert_eq!(
            nxt1,
            vec!["EIQsSW4KMrLzY1HQI9H_XxY6MyzhaFFXhG6fdBb5Wxta".to_string()]
        );

        // Create inception event

        let serder0 = InceptionEventBuilder::new(keys0.clone())
            .with_ndigs(nxt1.clone())
            .build()?;
        let pre = serder0.pre().unwrap();
        event_digs.push(serder0.said().unwrap().to_string());

        // Verify event properties
        assert_eq!(serder0.pre().unwrap(), signers[0].verfer().qb64());
        assert_eq!(serder0.ked()["s"].as_str(), Some("0"));
        assert_eq!(serder0.ked()["kt"].as_str(), Some("1"));
        assert_eq!(
            serder0.ked()["k"].as_array(),
            Some(
                &keys0
                    .iter()
                    .map(|k| SadValue::String(k.to_string()))
                    .collect::<Vec<SadValue>>()
            )
        );
        assert_eq!(
            serder0.ked()["n"].as_array(),
            Some(
                &nxt1
                    .iter()
                    .map(|n| SadValue::String(n.to_string()))
                    .collect::<Vec<SadValue>>()
            )
        );
        assert_eq!(
            serder0.said().unwrap(),
            "ECLgCt_5bprUe0SF1XCR94Zo5ShSEZO8cLf0dH3pwZxU"
        );

        // Sign the serialization
        let sig0 = match signers[0].sign(serder0.raw(), Some(0), None, None)? {
            Sigmat::Indexed(siger) => siger,
            _ => {
                return Err(KERIError::ValueError(
                    "Expected indexed signature".to_string(),
                ))
            }
        };

        // Verify signature
        assert!(signers[0].verfer().verify(sig0.raw(), serder0.raw())?);

        // Create Kever with the event
        let mut kever = KeverBuilder::new(Arc::new(&db))
            .with_serder(serder0.clone())
            .with_sigers(vec![sig0])
            .build()?;

        // Verify Kever state
        assert_eq!(kever.prefixer.as_ref().unwrap().qb64(), pre);
        assert_eq!(kever.sner.as_ref().unwrap().num(), 0u128);
        assert_eq!(
            kever.serder.as_ref().unwrap().said().unwrap(),
            event_digs[0]
        );
        assert_eq!(kever.ilk, Ilk::Icp);
        assert_eq!(
            kever.tholder.clone().unwrap().thold(),
            &TholderThold::Integer(1)
        );

        // Verify verfers in Kever match keys0
        let kever_verfers: Vec<String> = kever
            .verfers
            .as_ref()
            .unwrap()
            .iter()
            .map(|v| v.qb64())
            .collect();
        assert_eq!(kever_verfers, keys0);

        // Verify ndigs in Kever
        assert_eq!(kever.ndigs().clone(), nxt1);

        // Verify transferable and estOnly flags
        assert_eq!(kever.est_only, Some(false));
        assert!(kever.prefixer.as_ref().unwrap().transferable());

        let pigers = kever.fetch_prior_digers(None)?;
        assert!(pigers.is_none());

        // Event 1 Rotation Transferable
        // compute nxt digest from keys2
        let keys2 = vec![signers[2].verfer().qb64()];
        let ndiger2 = Diger::from_ser(&signers[2].verfer().qb64b(), None)?;
        let nxt2 = vec![ndiger2.qb64()];
        assert_eq!(
            nxt2,
            vec!["EHuvLs1hmwxo4ImDoCpaAermYVQhiPsPDNaZsz4bcgko".to_string()]
        );

        let serder1 = RotateEventBuilder::new(
            pre.clone(),
            keys1.clone(),
            serder0.said().unwrap().to_string(),
        )
        .with_sn(1)
        .with_ndigs(nxt2.clone())
        .build()?;

        event_digs.push(serder1.said().unwrap().to_string());

        assert_eq!(serder1.ked()["i"].as_str().unwrap(), pre);
        assert_eq!(serder1.ked()["s"].as_str().unwrap(), "1");
        assert_eq!(serder1.ked()["kt"].as_str().unwrap(), "1");
        assert_eq!(
            serder1.ked()["k"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_str().unwrap())
                .collect::<Vec<&str>>(),
            keys1
        );
        assert_eq!(
            serder1.ked()["n"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_str().unwrap())
                .collect::<Vec<&str>>(),
            nxt2
        );
        assert_eq!(
            serder1.ked()["p"].as_str().unwrap(),
            serder0.said().unwrap()
        );

        // sign serialization and verify signature
        let sig1 = match signers[1].sign(serder1.raw(), Some(0), None, None)? {
            Sigmat::Indexed(siger) => siger,
            _ => {
                return Err(KERIError::ValueError(
                    "Expected indexed signature".to_string(),
                ))
            }
        };
        assert!(signers[1].verfer().verify(sig1.raw(), serder1.raw())?);

        // update key event verifier state
        kever.update(
            serder1.clone(),
            vec![sig1],
            None,
            None,
            None,
            None,
            None,
            false,
            false,
            false,
        )?;
        assert_eq!(kever.prefixer.as_ref().unwrap().qb64(), pre);
        assert_eq!(kever.sner.as_ref().unwrap().num(), 1u128);
        assert_eq!(
            kever.serder.as_ref().unwrap().said().unwrap(),
            event_digs[1]
        );
        assert_eq!(kever.ilk, Ilk::Rot);

        // Verify verfers in Kever match keys1
        let kever_verfers: Vec<String> = kever
            .verfers
            .as_ref()
            .unwrap()
            .iter()
            .map(|v| v.qb64())
            .collect();
        assert_eq!(kever_verfers, keys1);

        // Verify ndigs in Kever
        assert_eq!(kever.ndigs().clone(), nxt2);

        let pigers = kever.fetch_prior_digers(None)?;
        assert!(pigers.is_some());
        let pigers_qb64: Vec<String> = pigers.unwrap().iter().map(|d| d.qb64()).collect();
        assert_eq!(pigers_qb64, nxt1);

        // Event 2 Rotation Transferable
        // compute nxt digest from keys3
        let keys3 = vec![signers[3].verfer().qb64()];
        let ndiger3 = Diger::from_ser(&signers[3].verfer().qb64b(), None)?;
        let nxt3 = vec![ndiger3.qb64()];

        let serder2 = RotateEventBuilder::new(
            pre.clone(),
            keys2.clone(),
            serder1.said().unwrap().to_string(),
        )
        .with_sn(2)
        .with_ndigs(nxt3.clone())
        .build()?;

        event_digs.push(serder2.said().unwrap().to_string());

        assert_eq!(serder2.ked()["i"].as_str().unwrap(), pre);
        assert_eq!(serder2.ked()["s"].as_str().unwrap(), "2");
        assert_eq!(
            serder2.ked()["k"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_str().unwrap())
                .collect::<Vec<&str>>(),
            keys2
        );
        assert_eq!(
            serder2.ked()["n"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_str().unwrap())
                .collect::<Vec<&str>>(),
            nxt3
        );
        assert_eq!(
            serder2.ked()["p"].as_str().unwrap(),
            serder1.said().unwrap()
        );

        // sign serialization and verify signature
        let sig2 = match signers[2].sign(serder2.raw(), Some(0), None, None)? {
            Sigmat::Indexed(siger) => siger,
            _ => {
                return Err(KERIError::ValueError(
                    "Expected indexed signature".to_string(),
                ))
            }
        };
        assert!(signers[2].verfer().verify(sig2.raw(), serder2.raw())?);

        // update key event verifier state
        kever.update(
            serder2.clone(),
            vec![sig2],
            None,
            None,
            None,
            None,
            None,
            false,
            false,
            false,
        )?;
        assert_eq!(kever.prefixer.as_ref().unwrap().qb64(), pre);
        assert_eq!(kever.sner.as_ref().unwrap().num(), 2u128);
        assert_eq!(
            kever.serder.as_ref().unwrap().said().unwrap(),
            event_digs[2]
        );
        assert_eq!(kever.ilk, Ilk::Rot);

        // Verify verfers in Kever match keys2
        let kever_verfers: Vec<String> = kever
            .verfers
            .as_ref()
            .unwrap()
            .iter()
            .map(|v| v.qb64())
            .collect();
        assert_eq!(kever_verfers, keys2);

        // Verify ndigs in Kever
        assert_eq!(kever.ndigs().clone(), nxt3);

        let pigers = kever.fetch_prior_digers(None)?;
        assert!(pigers.is_some());
        let pigers_qb64: Vec<String> = pigers.unwrap().iter().map(|d| d.qb64()).collect();
        assert_eq!(pigers_qb64, nxt2);

        // Event 3 Interaction
        let serder3 = InteractEventBuilder::new(pre.clone(), serder2.said().unwrap().to_string())
            .with_sn(3)
            .build()?;

        event_digs.push(serder3.said().unwrap().to_string());

        assert_eq!(serder3.ked()["i"].as_str().unwrap(), pre);
        assert_eq!(serder3.ked()["s"].as_str().unwrap(), "3");
        assert_eq!(
            serder3.ked()["p"].as_str().unwrap(),
            serder2.said().unwrap()
        );

        // sign serialization and verify signature
        let sig3 = match signers[2].sign(serder3.raw(), Some(0), None, None)? {
            Sigmat::Indexed(siger) => siger,
            _ => {
                return Err(KERIError::ValueError(
                    "Expected indexed signature".to_string(),
                ))
            }
        };
        assert!(signers[2].verfer().verify(sig3.raw(), serder3.raw())?);

        // update key event verifier state
        kever.update(
            serder3.clone(),
            vec![sig3],
            None,
            None,
            None,
            None,
            None,
            false,
            false,
            false,
        )?;
        assert_eq!(kever.prefixer.as_ref().unwrap().qb64(), pre);
        assert_eq!(kever.sner.as_ref().unwrap().num(), 3u128);
        assert_eq!(
            kever.serder.as_ref().unwrap().said().unwrap(),
            event_digs[3]
        );
        assert_eq!(kever.ilk, Ilk::Ixn);

        // Verify verfers in Kever match keys2 (no change)
        let kever_verfers: Vec<String> = kever
            .verfers
            .as_ref()
            .unwrap()
            .iter()
            .map(|v| v.qb64())
            .collect();
        assert_eq!(kever_verfers, keys2);

        // Verify ndigs in Kever (no change)
        assert_eq!(kever.ndigs().clone(), nxt3);

        let pigers = kever.fetch_prior_digers(None)?;
        assert!(pigers.is_some());
        let pigers_qb64: Vec<String> = pigers.unwrap().iter().map(|d| d.qb64()).collect();
        assert_eq!(pigers_qb64, nxt2); // digs from rot before rot before ixn

        // Event 4 Interaction
        let serder4 = InteractEventBuilder::new(pre.clone(), serder3.said().unwrap().to_string())
            .with_sn(4)
            .build()?;

        event_digs.push(serder4.said().unwrap().to_string());

        assert_eq!(serder4.ked()["i"].as_str().unwrap(), pre);
        assert_eq!(serder4.ked()["s"].as_str().unwrap(), "4");
        assert_eq!(
            serder4.ked()["p"].as_str().unwrap(),
            serder3.said().unwrap()
        );

        // sign serialization and verify signature
        let sig4 = match signers[2].sign(serder4.raw(), Some(0), None, None)? {
            Sigmat::Indexed(siger) => siger,
            _ => {
                return Err(KERIError::ValueError(
                    "Expected indexed signature".to_string(),
                ))
            }
        };
        assert!(signers[2].verfer().verify(sig4.raw(), serder4.raw())?);

        // update key event verifier state
        kever.update(
            serder4.clone(),
            vec![sig4],
            None,
            None,
            None,
            None,
            None,
            false,
            false,
            false,
        )?;
        assert_eq!(kever.prefixer.as_ref().unwrap().qb64(), pre);
        assert_eq!(kever.sner.as_ref().unwrap().num(), 4u128);
        assert_eq!(
            kever.serder.as_ref().unwrap().said().unwrap(),
            event_digs[4]
        );
        assert_eq!(kever.ilk, Ilk::Ixn);

        // Verify verfers in Kever match keys2 (no change)
        let kever_verfers: Vec<String> = kever
            .verfers
            .as_ref()
            .unwrap()
            .iter()
            .map(|v| v.qb64())
            .collect();
        assert_eq!(kever_verfers, keys2);

        // Verify ndigs in Kever (no change)
        assert_eq!(kever.ndigs().clone(), nxt3);

        let pigers = kever.fetch_prior_digers(None)?;
        assert!(pigers.is_some());
        let pigers_qb64: Vec<String> = pigers.unwrap().iter().map(|d| d.qb64()).collect();
        assert_eq!(pigers_qb64, nxt2); // digs from rot before rot before ixn ixn

        // Event 5 Rotation Transferable
        // compute nxt digest from keys4
        let keys4 = vec![signers[4].verfer().qb64()];
        let ndiger4 = Diger::from_ser(&signers[4].verfer().qb64b(), None)?;
        let nxt4 = vec![ndiger4.qb64()];

        let serder5 = RotateEventBuilder::new(
            pre.clone(),
            keys3.clone(),
            serder4.said().unwrap().to_string(),
        )
        .with_sn(5)
        .with_ndigs(nxt4.clone())
        .build()?;

        event_digs.push(serder5.said().unwrap().to_string());

        assert_eq!(serder5.ked()["i"].as_str().unwrap(), pre);
        assert_eq!(serder5.ked()["s"].as_str().unwrap(), "5");
        assert_eq!(
            serder5.ked()["k"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_str().unwrap())
                .collect::<Vec<&str>>(),
            keys3
        );
        assert_eq!(
            serder5.ked()["n"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_str().unwrap())
                .collect::<Vec<&str>>(),
            nxt4
        );
        assert_eq!(
            serder5.ked()["p"].as_str().unwrap(),
            serder4.said().unwrap()
        );

        // sign serialization and verify signature
        let sig5 = match signers[3].sign(serder5.raw(), Some(0), None, None)? {
            Sigmat::Indexed(siger) => siger,
            _ => {
                return Err(KERIError::ValueError(
                    "Expected indexed signature".to_string(),
                ))
            }
        };
        assert!(signers[3].verfer().verify(sig5.raw(), serder5.raw())?);

        // update key event verifier state
        kever.update(
            serder5.clone(),
            vec![sig5],
            None,
            None,
            None,
            None,
            None,
            false,
            false,
            false,
        )?;
        assert_eq!(kever.prefixer.as_ref().unwrap().qb64(), pre);
        assert_eq!(kever.sner.as_ref().unwrap().num(), 5u128);
        assert_eq!(
            kever.serder.as_ref().unwrap().said().unwrap(),
            event_digs[5]
        );
        assert_eq!(kever.ilk, Ilk::Rot);

        // Verify verfers in Kever match keys3
        let kever_verfers: Vec<String> = kever
            .verfers
            .as_ref()
            .unwrap()
            .iter()
            .map(|v| v.qb64())
            .collect();
        assert_eq!(kever_verfers, keys3);

        // Verify ndigs in Kever
        assert_eq!(kever.ndigs().clone(), nxt4);

        let pigers = kever.fetch_prior_digers(None)?;
        assert!(pigers.is_some());
        let pigers_qb64: Vec<String> = pigers.unwrap().iter().map(|d| d.qb64()).collect();
        assert_eq!(pigers_qb64, nxt3); // digs from rot before ixn ixn before rot

        // Event 6 Interaction
        let serder6 = InteractEventBuilder::new(pre.clone(), serder5.said().unwrap().to_string())
            .with_sn(6)
            .build()?;

        event_digs.push(serder6.said().unwrap().to_string());

        assert_eq!(serder6.ked()["i"].as_str().unwrap(), pre);
        assert_eq!(serder6.ked()["s"].as_str().unwrap(), "6");
        assert_eq!(
            serder6.ked()["p"].as_str().unwrap(),
            serder5.said().unwrap()
        );

        // sign serialization and verify signature
        let sig6 = match signers[3].sign(serder6.raw(), Some(0), None, None)? {
            Sigmat::Indexed(siger) => siger,
            _ => {
                return Err(KERIError::ValueError(
                    "Expected indexed signature".to_string(),
                ))
            }
        };
        assert!(signers[3].verfer().verify(sig6.raw(), serder6.raw())?);

        // update key event verifier state
        kever.update(
            serder6.clone(),
            vec![sig6],
            None,
            None,
            None,
            None,
            None,
            false,
            false,
            false,
        )?;
        assert_eq!(kever.prefixer.as_ref().unwrap().qb64(), pre);
        assert_eq!(kever.sner.as_ref().unwrap().num(), 6u128);
        assert_eq!(
            kever.serder.as_ref().unwrap().said().unwrap(),
            event_digs[6]
        );
        assert_eq!(kever.ilk, Ilk::Ixn);

        // Verify verfers in Kever match keys3 (no change)
        let kever_verfers: Vec<String> = kever
            .verfers
            .as_ref()
            .unwrap()
            .iter()
            .map(|v| v.qb64())
            .collect();
        assert_eq!(kever_verfers, keys3);

        // Verify ndigs in Kever (no change)
        assert_eq!(kever.ndigs().clone(), nxt4);

        // Event 7 Rotation to null NonTransferable Abandon
        let serder7 = RotateEventBuilder::new(
            pre.clone(),
            keys4.clone(),
            serder6.said().unwrap().to_string(),
        )
        .with_sn(7)
        .build()?; // Empty ndigs for non-transferable rotation

        event_digs.push(serder7.said().unwrap().to_string());

        assert_eq!(serder7.ked()["i"].as_str().unwrap(), pre);
        assert_eq!(serder7.ked()["s"].as_str().unwrap(), "7");
        assert_eq!(
            serder7.ked()["k"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_str().unwrap())
                .collect::<Vec<&str>>(),
            keys4
        );
        // Check for empty ndigs list
        assert_eq!(serder7.ked()["n"].as_array().unwrap().len(), 0);
        assert_eq!(
            serder7.ked()["p"].as_str().unwrap(),
            serder6.said().unwrap()
        );

        // sign serialization and verify signature
        let sig7 = match signers[4].sign(serder7.raw(), Some(0), None, None)? {
            Sigmat::Indexed(siger) => siger,
            _ => {
                return Err(KERIError::ValueError(
                    "Expected indexed signature".to_string(),
                ))
            }
        };
        assert!(signers[4].verfer().verify(sig7.raw(), serder7.raw())?);

        // update key event verifier state
        kever.update(
            serder7.clone(),
            vec![sig7],
            None,
            None,
            None,
            None,
            None,
            false,
            false,
            false,
        )?;
        assert_eq!(kever.prefixer.as_ref().unwrap().qb64(), pre);
        assert_eq!(kever.sner.as_ref().unwrap().num(), 7u128);
        assert_eq!(
            kever.serder.as_ref().unwrap().said().unwrap(),
            event_digs[7]
        );
        assert_eq!(kever.ilk, Ilk::Rot);

        // Verify verfers in Kever match keys4
        let kever_verfers: Vec<String> = kever
            .verfers
            .as_ref()
            .unwrap()
            .iter()
            .map(|v| v.qb64())
            .collect();
        assert_eq!(kever_verfers, keys4);

        // Verify ndigs in Kever are empty
        assert_eq!(kever.ndigs().len(), 0);

        // Verify the identifier is no longer transferable
        assert!(!kever.transferable());

        // Event 8 Interaction (should be rejected as identifier is non-transferable)
        let serder8 = InteractEventBuilder::new(pre.clone(), serder7.said().unwrap().to_string())
            .with_sn(8)
            .build()?;

        assert_eq!(serder8.ked()["i"].as_str().unwrap(), pre);
        assert_eq!(serder8.ked()["s"].as_str().unwrap(), "8");
        assert_eq!(
            serder8.ked()["p"].as_str().unwrap(),
            serder7.said().unwrap()
        );

        // sign serialization and verify signature
        let sig8 = match signers[4].sign(serder8.raw(), Some(0), None, None)? {
            Sigmat::Indexed(siger) => siger,
            _ => {
                return Err(KERIError::ValueError(
                    "Expected indexed signature".to_string(),
                ))
            }
        };
        assert!(signers[4].verfer().verify(sig8.raw(), serder8.raw())?);

        // update key event verifier state - should fail with ValidationError
        let result = kever.update(
            serder8.clone(),
            vec![sig8.clone()],
            None,
            None,
            None,
            None,
            None,
            false,
            false,
            false,
        );
        assert!(result.is_err());
        assert!(matches!(result, Err(KERIError::ValidationError(_))));

        // Event 8 Rotation (should also be rejected as identifier is non-transferable)
        let keys5 = vec![signers[5].verfer().qb64()];
        let nxt5 = vec![ndiger4.qb64()]; // reuse ndiger4 as in Python example

        let serder8_rot = RotateEventBuilder::new(
            pre.clone(),
            keys5.clone(),
            serder7.said().unwrap().to_string(),
        )
        .with_sn(8)
        .with_ndigs(nxt5.clone())
        .build()?;

        assert_eq!(serder8_rot.ked()["i"].as_str().unwrap(), pre);
        assert_eq!(serder8_rot.ked()["s"].as_str().unwrap(), "8");
        assert_eq!(
            serder8_rot.ked()["p"].as_str().unwrap(),
            serder7.said().unwrap()
        );

        // sign serialization and verify signature
        let sig8_rot = match signers[4].sign(serder8_rot.raw(), Some(0), None, None)? {
            Sigmat::Indexed(siger) => siger,
            _ => {
                return Err(KERIError::ValueError(
                    "Expected indexed signature".to_string(),
                ))
            }
        };
        assert!(signers[4]
            .verfer()
            .verify(sig8_rot.raw(), serder8_rot.raw())?);

        // update key event verifier state - should fail with ValidationError
        let result = kever.update(
            serder8_rot,
            vec![sig8_rot],
            None,
            None,
            None,
            None,
            None,
            false,
            false,
            false,
        );
        assert!(result.is_err());
        assert!(matches!(result, Err(KERIError::ValidationError(_))));

        let mut db_digs = Vec::new();
        let val_iter = kever.db.kels.get_on_iter::<_, Vec<u8>>(&[&pre], 0)?;

        for val_result in val_iter {
            let raw_bytes = val_result?;
            let string_val = String::from_utf8(raw_bytes).expect("Invalid UTF-8 sequence");
            db_digs.push(string_val);
        }

        assert_eq!(db_digs, event_digs);

        Ok(())
    }
}
