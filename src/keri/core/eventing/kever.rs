use num_bigint::BigUint;
use crate::cesr::dater::Dater;
use crate::cesr::indexing::Indexer;
use crate::cesr::indexing::siger::Siger;
use crate::cesr::number::Number;
use crate::cesr::prefixer::Prefixer;
use crate::cesr::saider::Saider;
use crate::cesr::seqner::Seqner;
use crate::cesr::tholder::{Tholder, TholderSith};
use crate::cesr::verfer::Verfer;
use crate::keri::core::serdering::{Serder, SerderKERI};
use crate::keri::db::basing::{Baser, EventSourceRecord, KeyStateRecord};
use crate::keri::{Ilk, KERIError};
use crate::keri::db::dbing::keys::sn_key;
use crate::Matter;

pub struct Kever<'db> {
    pub db: Baser<'db>,
    version: String,      // Version of KERI protocol
    ilk: Ilk,          // Event type ilk
    delpre: Option<String>, // Delegator prefix if any
    delegated: bool,      // True if delegated event, False otherwise
    fner: Option<Number>, // First seen ordinal number
    dater: Option<Dater>, // First seen timestamp
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
                ilk, serder.ked()
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
            serder,
            sigers,
            wigers,
            wits,
            !check,
            delseqner,
            delsaider,
            firner,
            dater,
            local,
        )?;

        // Set first seen data if not in check mode
        if let Some(fn_num) = fn_num {
            kever.fner = Some(Number::from_num(&BigUint::from(fn_num))?);
            kever.dater = Some(Dater::from_dt(dts));
            kever.db.states.pin(&[kever.prefixer().qb64()], &kever.state()?);
        }

        Ok(kever)
    }

    // Stub methods required by the initializer

    fn reload(state: KeyStateRecord) -> Result<Self, KERIError> {
        todo!("Implement reload from state")
    }

    fn incept(&mut self, serder: SerderKERI) -> Result<(), KERIError> {
        todo!("Implement inception event validation and state setting")
    }

    fn config(&mut self, serder: SerderKERI, est_only: Option<bool>) -> Result<(), KERIError> {
        todo!("Implement config traits perms assignment")
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
        toader: Option<Tholder>,
        wits: Vec<String>,
        delseqner: Option<Seqner>,
        delsaider: Option<Saider>,
        eager: bool,
        local: bool,
    ) -> Result<(Vec<Siger>, Option<Vec<Siger>>, Option<String>, Option<Seqner>, Option<Saider>), KERIError> {
        // Unwrap verfers since they are required
        let verfers = match verfers {
            Some(v) => v,
            None => return Err(KERIError::ValueError("Missing verfers".to_string())),
        };

        // Unwrap toader or use default if None
        let toader = match toader {
            Some(t) => t,
            None => Tholder::new(None, None, Some(TholderSith::Integer(0)))?,
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
                sigers = sigers.into_iter()
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
        if !local && (
            self.locally_owned() ||
                self.locally_witnessed(&wits) ||
                self.locally_delegated(delpre.as_deref())
        ) {
            self.escrow_mf_event(
                &serder,
                sigers,
                wigers,
                delseqner.as_ref(),
                delsaider.as_ref(),
                local
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
        let werfers: Vec<Verfer> = wits.iter()
            .map(|wit| Verfer::new(Some(wit.as_bytes()), None))
            .collect::<Result<Vec<Verfer>, _>>()?;

        // Verify witness signatures
        let (wigers, windices) = match wigers {
            Some(wigers) => {
                let (wigers, windices) = self.verify_sigs(&serder.raw(), wigers, &werfers)?;
                (Some(wigers), windices)
            },
            None => (None, vec![]),
        };

        // Check if fully signed vs signing threshold
        let pre = self.prefixer().qb64();
        if !tholder.satisfy(&indices) {
            // Escrow partially signed event
            self.escrow_ps_event(
                &serder,
                sigers.clone(),
                wigers,
                delseqner.as_ref(),
                delsaider.as_ref(),
                local
            )?;

            return Err(KERIError::ValidationError(format!(
                "AID {}...{}: Failure satisfying sith = {:?} on sigs {:?} for evt = {:?}",
                &pre[..4],
                &pre[pre.len()-4..],
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
                        local
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
            if toader.num() != Some(0usize) {
                return Err(KERIError::ValidationError(format!(
                    "Invalid toad = {:?} for wits = {:?}",
                    toader.num(),
                    wits
                )));
            }
        } else {
            // Verify toad if not locally owned, membered, or witnessed
            if !(self.locally_owned() || self.locally_membered() || self.locally_witnessed(&wits)) {
                if !wits.is_empty() {
                    if toader.num() < Some(1) || toader.num() > Some(wits.len()) {
                        return Err(KERIError::ValidationError(format!(
                            "Invalid toad = {:?} for wits = {:?}",
                            toader.num(),
                            wits
                        )));
                    }
                } else if toader.num() != Some(0) {
                    return Err(KERIError::ValidationError(format!(
                        "Invalid toad = {:?} for wits = {:?}",
                        toader.num(),
                        wits
                    )));
                }

                if windices.len() < toader.num().unwrap() {
                    // Escrow partially witnessed event
                    if self.escrow_pw_event(
                        &serder,
                        wigers.clone(),
                        sigers,
                        delseqner.as_ref(),
                        delsaider.as_ref(),
                        local
                    )? {
                        // TODO: Push cue to query for witness receipts if needed
                    }

                    return Err(KERIError::ValidationError(format!(
                        "AID {}...{}: Failure satisfying toad={:?} on witness sigs {:?} for event={:?}",
                        &pre[..4],
                        &pre[pre.len()-4..],
                        toader.num().unwrap(),
                        wigers.map_or(vec![], |w| w.iter().map(|s| s.qb64()).collect::<Vec<String>>()),
                        serder.said()
                    )));
                }
            }
        }

        // Check delegation approval
        if self.locally_delegated(delpre.as_deref()) && !self.locally_owned() {
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
            local
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

    fn verify_sigs(&self, raw: &[u8], sigers: Vec<Siger>, verfers: &[Verfer])
                   -> Result<(Vec<Siger>, Vec<usize>), KERIError> {
        todo!("Implement verification of signatures and return unique verified sigers and indices")
    }

    fn locally_owned(&self) -> bool {
        todo!("Implement check if this kever's prefix is locally owned")
    }

    fn locally_witnessed(&self, wits: &[String]) -> bool {
        todo!("Implement check if this kever has local witnesses")
    }

    fn locally_delegated(&self, delpre: Option<&str>) -> bool {
        todo!("Implement check if this kever is locally delegated")
    }

    fn escrow_mf_event(&self, serder: &SerderKERI, sigers: Vec<Siger>, wigers: Option<Vec<Siger>>,
                       seqner: Option<&Seqner>, saider: Option<&Saider>, local: bool) -> Result<(), KERIError> {
        todo!("Implement escrow for misfit events")
    }

    fn escrow_ps_event(&self, serder: &SerderKERI, sigers: Vec<Siger>, wigers: Option<Vec<Siger>>,
                       seqner: Option<&Seqner>, saider: Option<&Saider>, local: bool) -> Result<(), KERIError> {
        todo!("Implement escrow for partially signed events")
    }

    fn escrow_pw_event(&self, serder: &SerderKERI, wigers: Option<Vec<Siger>>, sigers: Vec<Siger>,
                       seqner: Option<&Seqner>, saider: Option<&Saider>, local: bool) -> Result<bool, KERIError> {
        todo!("Implement escrow for partially witnessed events")
    }

    fn escrow_delegable_event(&self, serder: &SerderKERI, sigers: &[Siger],
                              wigers: Option<Vec<Siger>>, local: bool) -> Result<(), KERIError> {
        todo!("Implement escrow for delegable events")
    }

    fn exposeds(&self, sigers: &[Siger]) -> Result<Vec<usize>, KERIError> {
        todo!("Implement extraction of exposed signature indices")
    }

    fn ntholder(&self) -> Option<Tholder> {
        todo!("Implement getting next threshold holder")
    }

    fn validate_delegation(&self, serder: &SerderKERI, sigers: &[Siger], wigers: Option<Vec<Siger>>,
                           wits: &[String], delpre: Option<&str>, delseqner: Option<&Seqner>,
                           delsaider: Option<&Saider>, eager: bool, local: bool)
                           -> Result<(Option<Seqner>, Option<Saider>), KERIError> {
        todo!("Implement delegation validation")
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
            let sig_bytes: Vec<&[u8]> = sigers.iter()
                .map(|siger| siger.qb64().into_bytes().as_slice() )
                .collect();
            self.db.sigs.put(&dg_keys, &sig_bytes)?;
        }

        // Store witness signatures if provided
        if let Some(wigers) = &wigers {
            if !wigers.is_empty() {
                let wig_bytes: Vec<Vec<u8>> = wigers.iter()
                    .map(|siger| siger.qb64().into_bytes())
                    .collect();
                self.db.wigs.put(&dg_keys, &wig_bytes)?;
            }
        }

        // Store witnesses if provided
        if let Some(wits) = &wits {
            if !wits.is_empty() {
                // Convert witnesses to Prefixer instances
                // In Rust, we'd just store the witness prefixes directly
                self.db.wits.put(&dg_keys, wits)?;
            }
        }

        // Store serialized event (idempotent, may already be escrowed)
        self.db.evts.put(&dg_keys, &serder.raw())?;

        // Handle delegation for authorized delegated or issued event
        if self.delpre.is_some()
            && serder.ilk() != Some(Ilk::Ixn)
            && !self.locally_owned()
            && !self.locally_witnessed(wits.as_deref().unwrap_or(&[]))
            && seqner.is_some()
            && saider.is_some() {
            // Create authorizer (delegator/issuer) event seal couple
            let seqner = seqner.unwrap();
            let saider = saider.unwrap();
            let couple = [seqner.qb64().as_bytes(), saider.qb64().as_bytes()].concat();
            self.db.aess.put(&dg_keys, &couple)?;
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
            },
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
            match self.db.fels.put(&[&serder.preb().unwrap()], &serder.saidb().unwrap()) {
                Ok(fn_val) => {
                    fn_num = Some(fn_val);

                    // Use original timestamp from dater for cloned replay
                    let dts_to_set = match &dater {
                        Some(d) => d.dtsb().to_vec(),
                        None => dts_b.clone()
                    };

                    // Set first seen timestamp
                    self.db.dtss.pin(&dg_keys, &dts_to_set)?;

                    // Store first seen ordinal number
                    let fn_seqner = Number::from_num(&BigUint::from(fn_val))?;
                    self.db.fons.pin(&dg_keys, &fn_seqner)?;

                },
                Err(e) => return Err(KERIError::DatabaseError(format!("Failed to append to FEL: {}", e)))
            }
        }

        // Add event to Key Event Log
        let sn_key = sn_key(serder.preb().unwrap(), serder.sn().unwrap());
        self.db.kels.add(&[sn_key], &serder.saidb().unwrap())?;

        // Return first seen number (if any) and timestamp
        Ok((fn_num, now))
    }
    
    fn state(&self) -> Result<KeyStateRecord, KERIError> {
        todo!("Implement state record creation")
    }

    fn tholder(&self) -> Option<Tholder> {
        todo!()
    }

    fn toader(&self) -> Option<Tholder> {
        todo!()
    }

    fn wits(&self) -> Vec<String> {
        todo!()
    }

    fn prefixer(&self) -> Prefixer {
        todo!()
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
    use crate::keri::KERIError;

    #[test]
    fn test_kever() -> Result<(), KERIError> {
        Ok(())
    }

    #[test]
    fn test_kever_builder() -> Result<(), KERIError> {
        // This test would need proper test fixtures to be meaningful
        // Just showing example usage

        // Example usage:
        // let kever = KeverBuilder::new(db)
        //     .with_serder(serder)
        //     .with_sigers(sigers)
        //     .with_eager(true)
        //     .with_local(false)
        //     .build()?;

        Ok(())
    }
}
