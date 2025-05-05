use crate::cesr::dater::Dater;
use crate::cesr::diger::Diger;
use crate::cesr::indexing::siger::Siger;
use crate::cesr::indexing::Indexer;
use crate::cesr::number::Number;
use crate::cesr::prefixer::Prefixer;
use crate::cesr::saider::Saider;
use crate::cesr::seqner::Seqner;
use crate::cesr::tholder::Tholder;
use crate::cesr::verfer::Verfer;
use crate::keri::core::serdering::{Serder, SerderKERI};
use crate::keri::db::basing::{Baser, EventSourceRecord, KeyStateRecord, StateEERecord};
use crate::keri::db::dbing::keys::sn_key;
use crate::keri::{Ilk, KERIError};
use crate::Matter;
use num_bigint::BigUint;
use crate::cesr::trait_dex;
use crate::keri::core::eventing::state::StateEventBuilder;

/// Represents the location of the last establishment event
#[derive(Debug, Clone, PartialEq)]
pub struct LastEstLoc {
    /// Sequence number
    pub s: u64,
    /// Digest (said)
    pub d: String,
}

pub struct Kever<'db> {
    pub db: Baser<'db>,
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
    ndigs: Option<Vec<String>>,
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
        db: Baser<'db>,
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
            return Self::reload(state);
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
            ndigs: None,
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
            kever
                .db
                .states
                .pin(&[kever.prefixer().unwrap().qb64()], &kever.state()?);
        }

        Ok(kever)
    }

    // Stub methods required by the initializer

    fn reload(state: KeyStateRecord) -> Result<Self, KERIError> {
        todo!("Implement reload from state")
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
        let mut unique_wits = std::collections::HashSet::new();
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
        self.ndigs = Some(ndigs);
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
        if !local && self.locally_membered() {
            if let Some(indices) = self.locally_contributed_indices(&verfers) {
                sigers = sigers
                    .into_iter()
                    .filter(|siger| !indices.contains(&siger.index()))
                    .collect();

                // TODO: Implement cue pushing for remoteMemberedSig if needed
            }
        }

        // Verify signatures and get unique verified sigers and indices
        let (sigers, indices) = self.verify_sigs(&serder.raw(), sigers, &verfers)?;

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
                || self.locally_witnessed(&wits)
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
                self.prefixes(),
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
                let (wigers, windices) = self.verify_sigs(&serder.raw(), wigers, &werfers)?;
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
            if let Some(ntholder) = self.ntholder() {
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
            if !(self.locally_owned(None) || self.locally_membered() || self.locally_witnessed(&wits)) {
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

    // Stub methods needed by val_sigs_wigs_del

    fn locally_membered(&self) -> bool {
        todo!("Implement check if this kever's prefix is a local group member")
    }

    fn locally_contributed_indices(&self, verfers: &[Verfer]) -> Option<Vec<u32>> {
        todo!("Implement getting indices of locally contributed signatures")
    }

    /// Verifies signatures against verifiers and returns verified signatures and their indices
    ///
    /// Returns tuple of (vsigers, vindices) where:
    /// - vsigers is a list of unique verified sigers with assigned verfer
    /// - vindices is a list of indices from those verified sigers
    ///
    /// The returned vsigers and vindices may be used for threshold validation
    ///
    /// Assigns appropriate verfer from verfers to each siger based on siger index
    /// If no signatures verify then sigers and indices are empty
    ///
    /// # Arguments
    ///
    /// * `raw` - The signed data as bytes
    /// * `sigers` - A list of indexed Siger instances (signatures)
    /// * `verfers` - A list of Verfer instances (public keys)
    ///
    /// # Returns
    ///
    /// * `Result<(Vec<Siger>, Vec<usize>), KERIError>` - Tuple of verified sigers and their indices
    fn verify_sigs(
        &self,
        raw: &[u8],
        sigers: Vec<Siger>,
        verfers: &[Verfer],
    ) -> Result<(Vec<Siger>, Vec<usize>), KERIError> {
        if sigers.is_empty() {
            return Ok((Vec::new(), Vec::new()));
        }

        // Create a set of unique signatures to avoid duplicates
        // In Rust, we'll use a HashSet to collect unique sigers based on their qb64
        let mut unique_signatures = std::collections::HashSet::new();
        let mut unique_sigers = Vec::new();

        for siger in sigers {
            let qb64 = siger.qb64();
            if unique_signatures.insert(qb64) {
                unique_sigers.push(siger);
            }
        }

        // Create a vector to hold sigers with assigned verfers
        let mut usigers_with_verfers = Vec::new();

        // Assign verfers to each unique siger based on index
        for mut siger in unique_sigers {
            let index = siger.index() as usize;
            if index >= verfers.len() {
                // Log if index is out of bounds
                continue;
            }

            // Clone the verfer and assign it to the siger
            let verfer = verfers[index].clone();
            siger.set_verfer(verfer);
            usigers_with_verfers.push(siger);
        }

        // Create lists of verified sigers and their indices
        let mut vindices = Vec::new();
        let mut vsigers = Vec::new();

        // Verify each siger and collect valid ones
        for siger in usigers_with_verfers {
            // Get verfer from siger - it should be present now
            if let Some(verfer) = siger.verfer() {
                // Verify the signature
                match verfer.verify(siger.raw(), raw) {
                    Ok(true) => {
                        // Signature verified successfully
                        vindices.push(siger.index() as usize);
                        vsigers.push(siger);
                    }
                    Ok(false) => {
                        // Signature failed verification
                        print!("Signature failed verification for index {}", siger.index());
                    }
                    Err(err) => {
                        // Error during verification
                        print!(
                            "Error verifying signature at index {}: {:?}",
                            siger.index(),
                            err
                        );
                    }
                }
            } else {
                // This shouldn't happen if we properly assigned verfers above
                print!("Siger missing verfer at index {}", siger.index());
            }
        }

        Ok((vsigers, vindices))
    }

    fn locally_owned(&self, pre: Option<&str>) -> bool {
        match pre {
            Some(pre) => {
                self.db.prefixes.contains(pre)
                    && !self.db.groups.contains(pre)
            }
            None => {
                match self.prefixer() {
                    Some(prefixer) => {
                        self.db.prefixes.contains(&prefixer.qb64())
                            && !self.db.groups.contains(&prefixer.qb64())
                    }
                    None => false,
                }
            }
        }
    }

    fn locally_witnessed(&self, wits: &[String]) -> bool {
        todo!("Implement check if this kever has local witnesses")
    }

    fn locally_delegated(&self, delpre: Option<&str>) -> bool {
        match delpre {
            Some(delpre) => {
                self.locally_owned(Some(delpre))
            }
            None => false,
        }
    }
    
    pub fn verfers(&self) -> Option<Vec<Verfer>> {
        self.verfers.clone()
    }

    fn escrow_mf_event(
        &self,
        serder: &SerderKERI,
        sigers: Vec<Siger>,
        wigers: Option<Vec<Siger>>,
        seqner: Option<&Seqner>,
        saider: Option<&Saider>,
        local: bool,
    ) -> Result<(), KERIError> {
        todo!("Implement escrow for misfit events")
    }

    fn escrow_ps_event(
        &self,
        serder: &SerderKERI,
        sigers: Vec<Siger>,
        wigers: Option<Vec<Siger>>,
        seqner: Option<&Seqner>,
        saider: Option<&Saider>,
        local: bool,
    ) -> Result<(), KERIError> {
        todo!("Implement escrow for partially signed events")
    }

    fn escrow_pw_event(
        &self,
        serder: &SerderKERI,
        wigers: Option<Vec<Siger>>,
        sigers: Vec<Siger>,
        seqner: Option<&Seqner>,
        saider: Option<&Saider>,
        local: bool,
    ) -> Result<bool, KERIError> {
        todo!("Implement escrow for partially witnessed events")
    }

    fn escrow_delegable_event(
        &self,
        serder: &SerderKERI,
        sigers: &[Siger],
        wigers: Option<Vec<Siger>>,
        local: bool,
    ) -> Result<(), KERIError> {
        todo!("Implement escrow for delegable events")
    }

    fn exposeds(&self, sigers: &[Siger]) -> Result<Vec<usize>, KERIError> {
        todo!("Implement extraction of exposed signature indices")
    }

    fn ntholder(&self) -> Option<Tholder> {
        todo!("Implement getting next threshold holder")
    }

    fn validate_delegation(
        &self,
        serder: &SerderKERI,
        sigers: &[Siger],
        wigers: Option<Vec<Siger>>,
        wits: &[String],
        delpre: Option<&str>,
        delseqner: Option<&Seqner>,
        delsaider: Option<&Saider>,
        eager: bool,
        local: bool,
    ) -> Result<(Option<Seqner>, Option<Saider>), KERIError> {
        if delpre.is_none() {
            return Ok((None, None));
        }

        Err(KERIError::ValidationError(format!(
            "Delegation not yet implemented for this kever"
        )))
    }

    fn prefixes(&self) -> Vec<String> {
        todo!("Implement getting prefixes for this kever")
    }

    fn log_event(
        &self,
        serder: SerderKERI,
        sigers: Vec<Siger>,
        wigers: Option<Vec<Siger>>,
        wits: Option<Vec<String>>,
        first: bool,
        seqner: Option<Seqner>,
        saider: Option<Saider>,
        firner: Option<Seqner>,
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
            && !self.locally_witnessed(wits.as_deref().unwrap_or(&[]))
            && seqner.is_some()
            && saider.is_some()
        {
            // Create authorizer (delegator/issuer) event seal couple
            let seqner = seqner.unwrap();
            let saider = saider.unwrap();
            let couple = [seqner.qb64().as_bytes(), saider.qb64().as_bytes()].concat();
            self.db.aess.put(&dg_keys, &[&couple])?;
        }

        // Update event source record
        let esr = match self.db.esrs.get(&dg_keys) {
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
        let sn_key = sn_key(serder.preb().unwrap(), serder.sn().unwrap());
        self.db.kels.add(&[sn_key], &serder.saidb().unwrap())?;

        // Return first seen number (if any) and timestamp
        Ok((fn_num, now))
    }

    /// Returns KeyStateRecord instance of current key state
    pub fn state(&self) -> Result<KeyStateRecord, KERIError> {
        // Ensure required fields are available
        let prefixer = self.prefixer().ok_or_else(||
            KERIError::ValueError("Missing prefixer in Kever state".to_string()))?;

        let tholder = self.tholder().ok_or_else(||
            KERIError::ValueError("Missing tholder in Kever state".to_string()))?;

        let serder = self.serder.as_ref().ok_or_else(||
            KERIError::ValueError("Missing serder in Kever state".to_string()))?;

        let sner = self.sner.as_ref().ok_or_else(||
            KERIError::ValueError("Missing sner in Kever state".to_string()))?;

        let fner = self.fner.as_ref().ok_or_else(||
            KERIError::ValueError("Missing fner in Kever state".to_string()))?;

        let dater = self.dater.as_ref().ok_or_else(||
            KERIError::ValueError("Missing dater in Kever state".to_string()))?;

        let verfers = self.verfers.as_ref().ok_or_else(||
            KERIError::ValueError("Missing verfers in Kever state".to_string()))?;

        let toader = self.toader().ok_or_else(||
            KERIError::ValueError("Missing toader in Kever state".to_string()))?;

        let last_est = self.last_est.as_ref().ok_or_else(||
            KERIError::ValueError("Missing last_est in Kever state".to_string()))?;

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
            prefixer.qb64(),          // pre
            sner.num() as u64, // sn
            pig,                      // pig
            serder.said().unwrap().to_string(),      // dig
            fner.num() as u64, // fn_
            self.ilk.to_string(),     // eilk
            keys,                     // keys
            eevt,                     // eevt
        )
            .with_stamp(dater.dts())      // stamp
            .with_sith(tholder.sith())    // sith
            .with_ndigs(ndigs)            // ndigs
            .with_toad(toader.num() as usize)  // toad
            .with_wits(wits)              // wits
            .with_cnfg(cnfg);             // cnfg

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
        let state_record = state_builder.build().map_err(|e| KERIError::ValueError(e.to_string()))?;

        Ok(state_record)
    }

    fn tholder(&self) -> Option<Tholder> {
        self.tholder.clone()
    }

    fn toader(&self) -> Option<Number> {
        self.toader.clone()
    }

    fn wits(&self) -> Vec<String> {
        self.wits.clone().unwrap_or_else(Vec::new)
    }

    fn prefixer(&self) -> Option<Prefixer> {
        self.prefixer.clone()
    }
}

/// KeverBuilder provides a builder pattern for constructing a Kever instance
/// Each optional parameter of Kever::new is represented by a with_* method
pub struct KeverBuilder<'db> {
    db: Baser<'db>,
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
    pub fn new(db: Baser<'db>) -> Self {
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
    use crate::cesr::{mtr_dex, pre_dex};
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
        let kever = KeverBuilder::new(db)
            .with_serder(tser0.clone())
            .with_sigers(vec![tsig0])
            .build()?;

        // Verify Kever properties
        assert_eq!(kever.prefixer().unwrap().qb64(), aid0);

        // These assertions would need proper implementation
        assert_eq!(kever.sner.clone().unwrap().num(), 0);
        assert_eq!(
            kever.verfers.clone().unwrap().iter().map(|v| v.qb64()).collect::<Vec<_>>(),
            vec![skp0.verfer().qb64()]
        );
        assert_eq!(kever.ndigs.clone().unwrap(), nxt);
        let prefixer = kever.prefixer().ok_or_else(||
            KERIError::ValueError("Missing prefixer in Kever".to_string()))?;

        // Test getting state from the database
        let state: KeyStateRecord = kever.db.states.get(&[&prefixer.qb64()])
            .expect("State not found").unwrap();

        // Get the sequence number from kever
        let sner = kever.sner.as_ref().ok_or_else(||
            KERIError::ValueError("Missing sner in Kever".to_string()))?;

        // Format sner.num as hex string for comparison
        let sner_hex = format!("{:x}", sner.num());

        // Test that state's sequence number matches kever's
        assert_eq!(state.s, sner_hex);
        assert_eq!(state.s, "0"); // Assert sequence is 0

        // Get the serder from kever
        let serder = kever.serder.as_ref().ok_or_else(||
            KERIError::ValueError("Missing serder in Kever".to_string()))?;

        // Test getting feqner (first seen ordinal) from db
        let feqner: Number = kever.db.fons.get(&[&prefixer.qb64(), &serder.said().unwrap().to_string()])?.unwrap();
            
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
        let verfers = kever.verfers.as_ref().ok_or_else(||
            KERIError::ValueError("Missing verfers in Kever".to_string()))?;

        // Extract keys from state record
        let state_keys = ksr.k;

        // Extract qb64 keys from verfers
        let verfer_keys: Vec<String> = verfers.iter()
            .map(|verfer| verfer.qb64())
            .collect();

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

        let result = KeverBuilder::new(db).build();

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
}
