use crate::cesr::cigar::Cigar;
use crate::cesr::counting::{ctr_dex_1_0, BaseCounter, Counter};
use crate::cesr::diger::Diger;
use crate::cesr::indexing::siger::Siger;
use crate::cesr::prefixer::Prefixer;
use crate::cesr::saider::Saider;
use crate::cesr::seqner::Seqner;
use crate::cesr::signing::Sigmat;
use crate::cesr::tholder::{Tholder, TholderSith};
use crate::cesr::verfer::Verfer;
use crate::cesr::{mtr_dex, trait_dex, Tiers};
use crate::cesr::{Matter, Parsable};
use crate::hio::hicting::Mict;
use crate::keri::app::configing::Configer;
use crate::keri::app::keeping::creators::Algos;
use crate::keri::app::keeping::{Keeper, Manager};
use crate::keri::core::eventing::incept::InceptionEventBuilder;
use crate::keri::core::eventing::interact::InteractEventBuilder;
use crate::keri::core::eventing::kever::Kever;
use crate::keri::core::eventing::kevery::Kevery;
use crate::keri::core::eventing::messagize;
use crate::keri::core::eventing::query::QueryEventBuilder;
use crate::keri::core::eventing::receipt::ReceiptEventBuilder;
use crate::keri::core::eventing::reply::ReplyEventBuilder;
use crate::keri::core::eventing::rotate::RotateEventBuilder;
use crate::keri::core::eventing::{Seal, SealEvent, SealLast};
use crate::keri::core::parsing::Parser;
use crate::keri::core::routing::{Revery, Router};
use crate::keri::core::serdering::{Rawifiable, SadValue, Sadder, Serder, SerderKERI};
use crate::keri::db::basing::{Baser, EndpointRecord, HabitatRecord, LocationRecord};
use crate::keri::db::dbing::keys::{dg_key, sn_key};
use crate::keri::KERIError;
use crate::keri::KERIError::{ConfigurationError, MissingEntryError, ValidationError};
use crate::keri::{Ilks, Roles};
use indexmap::{IndexMap, IndexSet};
use serde_json;
use std::collections::{HashMap, VecDeque};
use std::ops::{Deref, DerefMut};
use std::str::FromStr;
use std::sync::Arc;
use tracing::{debug, info, warn};

pub struct BaseHab<'db, R> {
    pub ks: Keeper<'db>,
    pub db: Baser<'db>,
    pub mgr: Manager<'db>,
    pub rtr: Option<Arc<Router>>,
    pub rvy: Revery<'db>, // Added missing field
    pub kvy: Kevery<'db>,
    pub psr: Parser<'db, R>,
    pub name: String,
    pub ns: Option<String>,
    pub pre: Option<String>,
    pub temp: bool,
    pub inited: bool,
    pub delpre: Option<String>,
}

impl<'db, R> BaseHab<'db, R> {
    pub fn new(
        ks: Keeper<'db>,
        db: Baser<'db>,
        mgr: Manager<'db>,
        rtr: Option<Arc<Router>>,
        rvy: Revery<'db>,
        kvy: Kevery<'db>,
        psr: Parser<'db, R>,
        name: String,
        ns: Option<String>,
        pre: Option<String>,
        temp: bool,
    ) -> Result<Self, KERIError> {
        let mut hab = BaseHab {
            ks,
            db,
            mgr,
            rtr,
            rvy,
            kvy,
            psr,
            name,
            ns,
            pre,
            temp,
            inited: false,
            delpre: None,
        };

        Ok(hab)
    }

    /// Create inception event with verifiers, threshold settings, witnesses, etc.
    pub fn make(
        &mut self,
        d_n_d: Option<bool>,
        code: Option<&str>,
        data: Option<Vec<u8>>,
        delpre: Option<String>,
        est_only: Option<bool>,
        isith: Option<Tholder>,
        verfers: Vec<Verfer>,
        nsith: Option<Tholder>,
        digers: Option<Vec<Diger>>,
        toad: Option<u32>,
        wits: Option<Vec<String>>,
    ) -> Result<SerderKERI, KERIError> {
        if self.pre.is_some() {
            return Err(ValidationError("Habitat already incepted".to_string()));
        }

        let d_n_d = d_n_d.unwrap_or(false);
        let est_only = est_only.unwrap_or(false);
        let toad = toad.unwrap_or(0);
        let wits = wits.unwrap_or_default();
        let data = data.unwrap_or_default();

        let icount = verfers.len();
        let ncount = if let Some(ref digers) = digers {
            digers.len()
        } else {
            0
        };

        // Convert Tholder to TholderSith - if not provided, compute defaults
        let isith_sith = if let Some(isith) = isith {
            isith.sith()
        } else {
            let threshold = std::cmp::max(1, (icount as f64 / 2.0).ceil() as usize);
            TholderSith::Integer(threshold)
        };

        let nsith_sith = if let Some(nsith) = nsith {
            nsith.sith()
        } else {
            let threshold = std::cmp::max(0, (ncount as f64 / 2.0).ceil() as usize);
            TholderSith::Integer(threshold)
        };

        // Build configuration array
        let mut cnfg = Vec::new();
        if est_only {
            cnfg.push(trait_dex::EST_ONLY.to_string());
        }
        if d_n_d {
            cnfg.push(trait_dex::DO_NOT_DELEGATE.to_string());
        }

        // Store delegator prefix if provided
        self.delpre = delpre.clone();

        // Extract keys from verfers
        let keys: Vec<String> = verfers.iter().map(|verfer| verfer.qb64()).collect();

        // Extract next key digests from digers if provided
        let ndigs: Vec<String> = if let Some(digers) = digers {
            digers.iter().map(|diger| diger.qb64()).collect()
        } else {
            Vec::new()
        };

        // Convert data to SadValue format if provided
        let sad_data: Vec<SadValue> = if !data.is_empty() {
            // For now, just convert bytes to string - this may need more sophisticated conversion
            vec![SadValue::String(String::from_utf8_lossy(&data).to_string())]
        } else {
            Vec::new()
        };

        // Create the inception event using the builder
        let mut builder = InceptionEventBuilder::new(keys)
            .with_isith(isith_sith)
            .with_nsith(nsith_sith)
            .with_ndigs(ndigs)
            .with_toad(toad as usize)
            .with_wits(wits)
            .with_cnfg(cnfg)
            .with_data(sad_data);

        // Set derivation code if provided
        if let Some(code) = code {
            builder = builder.with_code(code.to_string());
        }

        // Set delegator prefix if this is a delegated inception
        if let Some(ref delpre) = self.delpre {
            builder = builder.with_delpre(delpre.clone());
        }

        // Build the serder
        let serder = builder.build()?;

        Ok(serder)
    }

    pub fn save(&mut self, habord: &HabitatRecord) -> Result<(), KERIError> {
        // Ensure we have a prefix
        let pre = self.pre.as_ref().ok_or_else(|| {
            KERIError::ValueError("Cannot save habitat without prefix".to_string())
        })?;

        // Save the habitat record keyed by prefix
        self.db
            .habs
            .pin(&[pre.as_bytes()], habord)
            .map_err(|e| KERIError::DatabaseError(format!("Failed to save habitat: {}", e)))?;

        // Handle namespace - empty string if None
        let ns = self.ns.as_deref().unwrap_or("");

        // Check if name already exists
        let existing: Option<Vec<u8>> = self
            .db
            .names
            .get(&[ns.as_bytes(), self.name.as_bytes()])
            .map_err(|e| {
            KERIError::DatabaseError(format!("Failed to check existing name: {}", e))
        })?;

        if existing.is_some() {
            return Err(KERIError::ValueError(
                "AID already exists with that name".to_string(),
            ));
        }

        // Pin the name to prefix mapping
        self.db
            .names
            .pin(
                &[ns.as_bytes(), self.name.as_bytes()],
                &pre.as_bytes().to_vec(),
            )
            .map_err(|e| KERIError::DatabaseError(format!("Failed to save name mapping: {}", e)))?;

        Ok(())
    }

    pub fn reconfigure(&self) {
        // Not yet implemented
    }

    /// Get own inception event serder
    pub fn iserder(&self) -> Result<SerderKERI, KERIError> {
        if let Some(ref pre) = self.pre {
            // Get digest of inception event (sequence number 0)
            let sn_key = sn_key(pre, 0);

            let dig = self.db.get_ke_last(&sn_key)?.ok_or_else(|| {
                ConfigurationError(format!(
                    "Missing inception event in KEL for Habitat pre={}",
                    pre
                ))
            })?;
            let dg_key = dg_key(pre, dig.as_bytes());

            let raw = self.db.get_evt(&dg_key)?.ok_or_else(|| {
                ConfigurationError(format!("Missing inception event for Habitat pre={}", pre))
            })?;
            SerderKERI::from_raw(&raw, None).map_err(|e| {
                ValidationError(format!("Failed to deserialize inception event: {}", e))
            })
        } else {
            Err(ConfigurationError("No prefix set for habitat".to_string()))
        }
    }

    /// Get all kevers from the local database
    pub fn kevers(&self) -> &HashMap<String, Kever<'db>> {
        &self.kvy.kevers
    }

    /// Check if this habitat is accepted into local KEL
    pub fn accepted(&self) -> bool {
        // In Python: return self.pre in self.kevers
        // This checks if the habitat's prefix exists in the kevers map
        if let Some(ref pre) = self.pre {
            self.kvy.kevers.contains_key(pre)
        } else {
            false
        }
    }

    /// Get the kever (key state) of the local controller
    pub fn kever(&self) -> Result<&Kever<'db>, KERIError> {
        if let Some(ref pre) = self.pre {
            self.kvy
                .kevers
                .get(pre)
                .ok_or_else(|| MissingEntryError(format!("No kever for prefix {}", pre)))
        } else {
            Err(ConfigurationError("No prefix set for habitat".to_string()))
        }
    }

    /// Get local prefixes for database
    pub fn prefixes(&self) -> IndexSet<String> {
        // Return prefixes from the database
        // This represents all locally controlled prefixes
        self.db.prefixes.clone()
    }

    /// Create inception event (alias for make)
    pub fn incept(
        &mut self,
        transferable: Option<bool>,
        code: Option<&str>,
        count: Option<u32>,
        ncount: Option<u32>,
        isith: Option<Tholder>,
        nsith: Option<Tholder>,
        toad: Option<u32>,
        wits: Option<Vec<String>>,
        cnfg: Option<Vec<&str>>,
        data: Option<Vec<u8>>,
        delpre: Option<String>,
    ) -> Result<SerderKERI, KERIError> {
        let transferable = transferable.unwrap_or(true);
        let count = count.unwrap_or(1);
        let ncount = ncount.unwrap_or(1);

        // Create verifiers and digesters using the manager
        let (verfers, digers) = self.mgr.incept(
            None,                  // icodes
            Some(count as usize),  // icount
            None,                  // icode - will use default
            None,                  // ncodes
            Some(ncount as usize), // ncount
            None,                  // ncode - will use default
            None,                  // dcode - will use default
            None,                  // algo
            None,                  // salt
            None,                  // stem
            None,                  // tier
            None,                  // rooted
            Some(transferable),
            Some(self.temp),
        )?;

        // Extract configuration flags from cnfg parameter
        let mut d_n_d = false;
        let mut est_only = false;
        if let Some(cnfg) = cnfg {
            for config in cnfg {
                match config {
                    "EO" => est_only = true, // EST_ONLY trait
                    "DND" => d_n_d = true,   // DO_NOT_DELEGATE trait
                    _ => {}                  // Ignore unknown configs
                }
            }
        }

        // Now call make with the proper parameters
        self.make(
            Some(d_n_d),    // d_n_d: Option<bool>
            code,           // code: Option<&str>
            data,           // data: Option<Vec<u8>>
            delpre,         // delpre: Option<String>
            Some(est_only), // est_only: Option<bool>
            isith,          // isith: Option<Tholder>
            verfers,        // verfers: Vec<Verfer>
            nsith,          // nsith: Option<Tholder>
            Some(digers),   // digers: Option<Vec<Diger>>
            toad,           // toad: Option<u32>
            wits,           // wits: Option<Vec<String>>
        )
    }

    /// Perform rotation operation
    pub fn rotate(
        &mut self,
        count: Option<u32>,
        ncount: Option<u32>,
        isith: Option<Tholder>,
        nsith: Option<Tholder>,
        toad: Option<u32>,
        cuts: Option<Vec<String>>,
        adds: Option<Vec<String>>,
        data: Option<Vec<u8>>,
    ) -> Result<Vec<u8>, KERIError> {
        if self.pre.is_none() {
            return Err(ValidationError("Habitat not incepted".to_string()));
        }

        // Get current kever state before rotation - this is the "prior next"
        let kever = self.kever()?;
        let pre = self.pre.as_ref().unwrap();

        // Set defaults for counts
        let ncount = ncount.unwrap_or(1);

        // Create new keys using the manager's rotate method with correct parameters
        let (verfers, digers) = self.mgr.rotate(
            pre.as_bytes(),        // pre: &[u8]
            None,                  // ncodes: Option<Vec<&str>>
            Some(ncount as usize), // ncount: Option<usize>
            None,                  // ncode: Option<&str> - will use default ED25519
            None,                  // dcode: Option<&str> - will use default BLAKE3_256
            Some(true),            // transferable: Option<bool>
            Some(self.temp),       // temp: Option<bool>
            Some(true),            // erase: Option<bool> - erase old keys
        )?;

        // Determine signing thresholds following Python logic
        let isith_sith = if let Some(isith) = isith {
            isith.sith()
        } else {
            // Use prior next threshold as default, or provide fallback if None
            kever
                .ntholder
                .as_ref()
                .map(|tholder| tholder.sith())
                .unwrap_or(TholderSith::Integer(1)) // Provide a sensible default
        };

        let nsith_sith = if let Some(nsith) = nsith {
            nsith.sith()
        } else {
            // Use new current as default (same as isith)
            isith_sith.clone()
        };

        // If still no thresholds, compute defaults from key counts
        let final_isith = if matches!(isith_sith, TholderSith::Integer(0)) {
            let threshold = std::cmp::max(1, (verfers.len() as f64 / 2.0).ceil() as usize);
            TholderSith::Integer(threshold)
        } else {
            isith_sith
        };

        let final_nsith = if matches!(nsith_sith, TholderSith::Integer(0)) {
            let threshold = std::cmp::max(0, (digers.len() as f64 / 2.0).ceil() as usize);
            TholderSith::Integer(threshold)
        } else {
            nsith_sith
        };

        // Extract keys from verfers
        let keys: Vec<String> = verfers.iter().map(|verfer| verfer.qb64()).collect();

        // Validate rotation against prior next key digests
        let mut indices = Vec::new();
        for (idx, prior_digers_vec) in kever.ndigers.iter().enumerate() {
            // Iterate over each Diger in the vector
            for prior_diger in prior_digers_vec {
                // Create digests from new verfers to compare with prior next digesters
                for verfer in &verfers {
                    let new_diger = Diger::from_ser(&mut verfer.qb64b(), Some(prior_diger.code()))?;
                    if new_diger.qb64() == prior_diger.qb64() {
                        indices.push(idx); // Remove 'as u32' - idx is already usize from enumerate()
                        break;
                    }
                }
            }
        }

        // Validate that new key set can satisfy prior next signing threshold
        if !kever
            .ntholder
            .as_ref()
            .map_or(false, |tholder| tholder.satisfy(&indices))
        {
            return Err(ValidationError(
                "Invalid rotation: new key set unable to satisfy prior next signing threshold"
                    .to_string(),
            ));
        }

        // Extract next key digests from digers
        let ndigs: Vec<String> = digers.iter().map(|diger| diger.qb64()).collect();

        // Convert data to SadValue format if provided
        let sad_data: Vec<SadValue> = if let Some(data) = data {
            if !data.is_empty() {
                // For now, just convert bytes to string - this may need more sophisticated conversion
                vec![SadValue::String(String::from_utf8_lossy(&data).to_string())]
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        };

        let said = kever
            .serder
            .as_ref()
            .ok_or_else(|| ValidationError("Missing serder".to_string()))?
            .said()
            .ok_or_else(|| ValidationError("Missing said in serder".to_string()))?
            .to_string();

        let num = kever
            .sner
            .as_ref()
            .ok_or_else(|| ValidationError("Missing sner".to_string()))?
            .num();

        // Build rotation event using the builder
        let mut builder = RotateEventBuilder::new(
            pre.clone(),
            keys,
            said, // previous event digest
        )
        .with_sn(num as usize + 1) // next sequence number
        .with_isith(final_isith)
        .with_nsith(final_nsith)
        .with_ndigs(ndigs)
        .with_wits(kever.wits())
        .with_data(sad_data);

        // Set witness threshold if provided
        if let Some(toad) = toad {
            builder = builder.with_toad(toad as usize);
        }

        // Set witness cuts and adds if provided
        if let Some(cuts) = cuts {
            builder = builder.with_cuts(cuts);
        }

        if let Some(adds) = adds {
            builder = builder.with_adds(adds);
        }

        // Set the appropriate ilk based on whether this is delegated
        if kever.delpre.is_some() {
            builder = builder.with_ilk(Ilks::DRT.to_string()); // Delegated rotation
        } else {
            builder = builder.with_ilk(Ilks::ROT.to_string()); // Regular rotation
        }

        // Build the serder
        let serder = builder.build()?;

        // Sign the rotation event
        let sigers = self.sign(
            &serder.raw(),
            Some(verfers),
            Some(true), // indexed
            None,       // indices
            None,       // ondices
            None,       // ponly
        )?;

        // Create message from serder and signatures
        let msg = messagize(&serder, Some(&sigers), None, None, None, false)
            .map_err(|e| KERIError::ValidationError(format!("Failed to create message: {}", e)))?;

        // Process the event to update key state
        match self.kvy.process_event(
            serder.clone(),
            sigers,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        ) {
            Ok(_) => {}
            Err(KERIError::MissingSignatureError(_)) => {}
            Err(e) => {
                return Err(KERIError::ValidationError(format!(
                    "Improper Habitat rotation for pre={}. Error: {}",
                    pre, e
                )));
            }
        }

        Ok(msg)
    }

    pub fn interact(&mut self, data: Option<Vec<u8>>) -> Result<Vec<u8>, KERIError> {
        // Get the current kever (key event state)
        let kever = self.kever()?;

        // Get the prefix - must exist for interaction
        let pre = self
            .pre
            .as_ref()
            .ok_or_else(|| ConfigurationError("No prefix set for habitat".to_string()))?;

        // Get the current sequence number and increment for next event
        let current_sn = kever
            .sner
            .as_ref()
            .ok_or_else(|| ValidationError("Missing sequence number in kever".to_string()))?
            .num();
        let next_sn = current_sn + 1;

        // Get the digest of the current event (prior event)
        let prior_dig = kever
            .serder
            .as_ref()
            .ok_or_else(|| ValidationError("Missing serder in kever".to_string()))?
            .said()
            .ok_or_else(|| ValidationError("Missing SAID in current event".to_string()))?
            .to_string();

        // Create interaction event using the builder
        let mut builder =
            InteractEventBuilder::new(pre.clone(), prior_dig).with_sn(next_sn as usize);

        // Add data if provided
        if let Some(data) = data {
            if !data.is_empty() {
                // Convert data to SadValue format - you can customize this based on your data format needs
                let sad_data = vec![SadValue::String(String::from_utf8_lossy(&data).to_string())];
                builder = builder.with_data_list(sad_data);
            }
        }

        // Build the serder
        let serder = builder.build()?;

        // Sign the interaction event
        let sigers = self.sign(
            &serder.raw(), // ser: serialized event to sign
            None,          // verfers: use current verfers from kever
            Some(true),    // indexed: create indexed signatures
            None,          // indices: let manager choose indices
            None,          // ondices: no specific ondices
            None,          // ponly: not ponly mode
        )?;

        // Create the complete message with serder and signatures
        let msg = messagize(&serder, Some(&sigers), None, None, None, false)
            .map_err(|e| ValidationError(format!("Failed to create message: {}", e)))?;

        // Process the event through kevery to update local state
        // This validates the event and updates the kever state
        match self.kvy.process_event(
            serder, // serder: the interaction event
            sigers, // sigers: signatures
            None,   // wigers: no witness signatures
            None,   // local: not specified
            None,   // cigars: no non-indexed signatures
            None,   // tsgs: no trans signatures
            None,   // tholder: no threshold
            None,   // toader: no toad threshold
            None,   // seqner: sequence number will be extracted
        ) {
            Ok(_) => {
                // Event processed successfully
            }
            Err(KERIError::MissingSignatureError(_)) => {
                // Missing signatures are acceptable for some scenarios
                // Continue processing
            }
            Err(e) => {
                // Any other error indicates improper interaction
                return Err(ValidationError(format!(
                    "Improper Habitat interaction for pre={}. Error: {}",
                    pre, e
                )));
            }
        }

        Ok(msg)
    }

    /// Sign given serialization using appropriate keys
    pub fn sign(
        &self,
        ser: &[u8],
        verfers: Option<Vec<Verfer>>,
        indexed: Option<bool>,
        indices: Option<Vec<u32>>,
        ondices: Option<Vec<Option<u32>>>,
        ponly: Option<bool>,
    ) -> Result<Vec<Siger>, KERIError> {
        let indexed = indexed.unwrap_or(true);
        let _ponly = ponly.unwrap_or(false);

        // If no verfers provided, use the current kever's verfers
        let verfers_to_use = if verfers.is_some() {
            verfers
        } else {
            if let Ok(kever) = self.kever() {
                kever.verfers.clone()
            } else {
                None
            }
        };

        // Delegate to the manager's sign method
        let signatures = self.mgr.sign(
            ser,
            None, // pubs
            verfers_to_use,
            Some(indexed),
            indices,
            ondices,
            self.pre.as_ref().map(|p| p.as_bytes()),
            None, // path
        )?;

        // Extract Siger instances from Sigmat enum
        signatures
            .into_iter()
            .map(|sig| match sig {
                Sigmat::Indexed(siger) => Ok(siger),
                Sigmat::NonIndexed(_) => Err(KERIError::ValidationError(
                    "Expected Siger but got Cigar - indexed signatures required".to_string(),
                )),
            })
            .collect()
    }

    pub fn decrypt(&self, ser: &[u8], verfers: Option<Vec<Verfer>>) -> Result<Vec<u8>, KERIError> {
        // If no verfers provided, use the current kever's verfers
        let verfers_to_use = if let Some(verfers) = verfers {
            Some(verfers)
        } else {
            // Get verfers from kever - these provide group signing keys when in group mode
            match self.kever() {
                Ok(kever) => kever.verfers.clone(),
                Err(_) => {
                    return Err(KERIError::ConfigurationError(
                        "No kever available and no verfers provided for decryption".to_string(),
                    ));
                }
            }
        };

        // Delegate to the manager's decrypt method
        // Note: The Python comment mentions this "should not use mgr.decrypt since it assumes qb64"
        // but says it's "just lucky its not yet a problem". We'll use it as intended for now.
        self.mgr.decrypt(
            ser,            // qb64: the ciphertext to decrypt
            None,           // pubs: not using public key strings
            verfers_to_use, // verfers: use the verfers we determined above
        )
    }

    pub fn query(
        &self,
        pre: &str,
        src: &str,
        query: Option<IndexMap<String, SadValue>>,
        route: Option<String>,
        reply_route: Option<String>,
        stamp: Option<String>,
    ) -> Result<Vec<u8>, KERIError> {
        // Start with provided query parameters or create new map
        let mut query_params = query.unwrap_or_else(|| IndexMap::new());

        // Set required query parameters
        query_params.insert("i".to_string(), SadValue::String(pre.to_string()));
        query_params.insert("src".to_string(), SadValue::String(src.to_string()));

        // Build the query event using QueryEventBuilder
        let mut builder = QueryEventBuilder::new().with_query(query_params);

        // Set optional parameters if provided
        if let Some(r) = route {
            builder = builder.with_route(r);
        }

        if let Some(rr) = reply_route {
            builder = builder.with_reply_route(rr);
        }

        if let Some(ts) = stamp {
            builder = builder.with_stamp(ts);
        }

        // Build the serder
        let serder = builder
            .build()
            .map_err(|e| ValidationError(format!("Failed to build query event: {}", e)))?;

        // Endorse the query with SealLast (last=true)
        self.endorse(&serder, Some(true), None)
    }

    pub fn endorse(
        &self,
        serder: &SerderKERI,
        last: Option<bool>,
        pipelined: Option<bool>,
    ) -> Result<Vec<u8>, KERIError> {
        let last = last.unwrap_or(false);
        let pipelined = pipelined.unwrap_or(true);

        // Get the current kever state
        let kever = self.kever()?;

        // Get the prefixer and check if it exists
        let prefixer = kever
            .prefixer
            .as_ref()
            .ok_or_else(|| ValidationError("Missing prefixer in kever".to_string()))?;

        // Check if the habitat's identifier is transferable
        if prefixer.transferable() {
            // For transferable identifiers, create indexed signatures with seals

            // Create appropriate seal based on 'last' parameter
            let seal = if last {
                // Create SealLast with just the identifier
                Seal::SealLast(SealLast::new(prefixer.qb64()))
            } else {
                // Create SealEvent with identifier, sequence number, and digest
                // Get the last establishment event info
                let last_est_sn = kever
                    .sner
                    .as_ref()
                    .ok_or_else(|| ValidationError("Missing sequence number in kever".to_string()))?
                    .num();

                let last_est_dig = kever
                    .serder
                    .as_ref()
                    .ok_or_else(|| ValidationError("Missing serder in kever".to_string()))?
                    .said()
                    .ok_or_else(|| ValidationError("Missing SAID in current event".to_string()))?
                    .to_string();

                Seal::SealEvent(SealEvent::new(
                    prefixer.qb64(),              // identifier prefix
                    format!("{:x}", last_est_sn), // sequence number as hex string
                    last_est_dig,                 // digest of last establishment event
                ))
            };

            // Sign the serder with indexed signatures
            let sigers = self.sign(
                &serder.raw(), // ser: serialized event to sign
                None,          // verfers: use current verfers from kever
                Some(true),    // indexed: create indexed signatures
                None,          // indices: let manager choose indices
                None,          // ondices: no specific ondices
                None,          // ponly: not ponly mode
            )?;

            // Create the endorsement message with serder, signatures, and seal
            let msg = messagize(
                serder,        // serder: the event being endorsed
                Some(&sigers), // sigers: indexed signatures
                Some(seal),    // seal: seal indicating endorser's state
                None,          // cigars: not used for transferable
                None,          // wigers: no witness signatures
                pipelined,     // pipelined: message format
            )
            .map_err(|e| ValidationError(format!("Failed to create endorsement message: {}", e)))?;

            Ok(msg)
        } else {
            // For non-transferable identifiers, create non-indexed signatures (cigars)

            // Sign the serder with non-indexed signatures
            let signatures = self.mgr.sign(
                &serder.raw(),                           // ser: serialized event to sign
                None,                                    // pubs: not using public key strings
                None,        // verfers: use current verfers from kever (handled by sign method)
                Some(false), // indexed: create non-indexed signatures
                None,        // indices: not applicable for non-indexed
                None,        // ondices: not applicable for non-indexed
                self.pre.as_ref().map(|p| p.as_bytes()), // pre: habitat prefix
                None,        // path: not specified
            )?;

            // Extract Cigar instances from Sigmat enum
            let cigars: Result<Vec<Cigar>, KERIError> = signatures.into_iter()
                .map(|sig| {
                    match sig {
                        Sigmat::NonIndexed(cigar) => Ok(cigar),
                        Sigmat::Indexed(_) => Err(KERIError::ValidationError(
                            "Expected Cigar but got Siger - non-indexed signatures required for non-transferable".to_string()
                        ))
                    }
                })
                .collect();

            let cigars = cigars?;

            // Create the endorsement message with serder and cigars (no seal for non-transferable)
            let msg = messagize(
                serder,        // serder: the event being endorsed
                None,          // sigers: not used for non-transferable
                None,          // seal: not used for non-transferable
                None,          // wigers: no witness signatures
                Some(&cigars), // cigars: non-indexed signatures
                pipelined,     // pipelined: message format
            )
            .map_err(|e| ValidationError(format!("Failed to create endorsement message: {}", e)))?;

            Ok(msg)
        }
    }
    pub fn exchange(&self) {
        // Not yet implemented
    }
    /// Create and process a receipt event for the given serder
    ///
    /// Creates a KERI receipt event for the provided event serder, signs it
    /// with the appropriate signature type based on transferability, and
    /// processes it into the local database.
    ///
    /// # Arguments
    /// * `serder` - The event serder to create a receipt for
    ///
    /// # Returns
    /// * `Result<Vec<u8>, KERIError>` - The complete receipt message bytes
    ///
    /// # Errors
    /// * `KERIError::ValidationError` - If receipt building, signing, or processing fails
    /// * `KERIError::ConfigurationError` - If habitat not properly initialized
    /// * `KERIError::MissingEntryError` - If required kever state is missing
    pub fn receipt(&mut self, serder: &SerderKERI) -> Result<Vec<u8>, KERIError> {
        // Extract event details from the provided serder
        let ked = serder.ked();

        // Get the identifier prefix from the event
        let pre = ked
            .get("i")
            .and_then(|v| match v {
                SadValue::String(s) => Some(s.clone()),
                _ => None,
            })
            .ok_or_else(|| ValidationError("Missing or invalid identifier in event".to_string()))?;

        // Get the sequence number from the event and convert from hex
        let sn_hex = ked
            .get("s")
            .and_then(|v| match v {
                SadValue::String(s) => Some(s.clone()),
                _ => None,
            })
            .ok_or_else(|| {
                ValidationError("Missing or invalid sequence number in event".to_string())
            })?;

        let sn = usize::from_str_radix(&sn_hex, 16)
            .map_err(|_| ValidationError("Invalid hex sequence number format".to_string()))?;

        // Get the SAID of the event
        let said = serder
            .said()
            .ok_or_else(|| ValidationError("Missing SAID in event serder".to_string()))?
            .to_string();

        // Create the receipt event using ReceiptEventBuilder
        let receipt_serder = ReceiptEventBuilder::new(pre, sn, said)
            .build()
            .map_err(|e| ValidationError(format!("Failed to build receipt event: {}", e)))?;

        // Get the current kever to determine signature type
        let kever = self.kever()?;

        // Get the prefixer and check transferability
        let prefixer = kever
            .prefixer
            .as_ref()
            .ok_or_else(|| ValidationError("Missing prefixer in kever".to_string()))?;

        let msg = if prefixer.transferable() {
            // For transferable identifiers, create indexed signatures with seal

            // Get the last establishment event info for the seal
            let last_est_sn = kever
                .sner
                .as_ref()
                .ok_or_else(|| ValidationError("Missing sequence number in kever".to_string()))?
                .num();

            let last_est_dig = kever
                .serder
                .as_ref()
                .ok_or_else(|| ValidationError("Missing serder in kever".to_string()))?
                .said()
                .ok_or_else(|| ValidationError("Missing SAID in current event".to_string()))?
                .to_string();

            // Create SealEvent with the last establishment event details
            let seal = Seal::SealEvent(SealEvent::new(
                self.pre
                    .as_ref()
                    .ok_or_else(|| ConfigurationError("No prefix set for habitat".to_string()))?
                    .clone(), // identifier prefix of the receiptor
                format!("{:x}", last_est_sn), // sequence number as hex string
                last_est_dig,                 // digest of last establishment event
            ));

            // Sign the original serder (not the receipt) with indexed signatures
            let sigers = self.sign(
                &serder.raw(), // Sign the original event, not the receipt
                None,          // verfers: use current verfers from kever
                Some(true),    // indexed: create indexed signatures
                None,          // indices: let manager choose indices
                None,          // ondices: no specific ondices
                None,          // ponly: not ponly mode
            )?;

            // Create the receipt message with receipt serder, signatures, and seal
            messagize(
                &receipt_serder, // serder: the receipt event
                Some(&sigers),   // sigers: indexed signatures
                Some(seal),      // seal: seal indicating receiptor's state
                None,            // cigars: not used for transferable
                None,            // wigers: no witness signatures
                true,            // pipelined: standard message format
            )
            .map_err(|e| ValidationError(format!("Failed to create receipt message: {}", e)))?
        } else {
            // For non-transferable identifiers, create non-indexed signatures (cigars)

            // Sign the original serder with non-indexed signatures
            let signatures = self.mgr.sign(
                &serder.raw(),                           // Sign the original event, not the receipt
                None,                                    // pubs: not using public key strings
                None,                                    // verfers: use current verfers from kever
                Some(false),                             // indexed: create non-indexed signatures
                None,                                    // indices: not applicable for non-indexed
                None,                                    // ondices: not applicable for non-indexed
                self.pre.as_ref().map(|p| p.as_bytes()), // pre: habitat prefix
                None,                                    // path: not specified
            )?;

            // Extract Cigar instances from Sigmat enum
            let cigars: Result<Vec<Cigar>, KERIError> = signatures.into_iter()
                .map(|sig| {
                    match sig {
                        Sigmat::NonIndexed(cigar) => Ok(cigar),
                        Sigmat::Indexed(_) => Err(KERIError::ValidationError(
                            "Expected Cigar but got Siger - non-indexed signatures required for non-transferable".to_string()
                        ))
                    }
                })
                .collect();

            let cigars = cigars?;

            // Create the receipt message with receipt serder and cigars (no seal for non-transferable)
            messagize(
                &receipt_serder, // serder: the receipt event
                None,            // sigers: not used for non-transferable
                None,            // seal: not used for non-transferable
                None,            // wigers: no witness signatures
                Some(&cigars),   // cigars: non-indexed signatures
                true,            // pipelined: standard message format
            )
            .map_err(|e| ValidationError(format!("Failed to create receipt message: {}", e)))?
        };

        // Process the receipt message locally into the database
        // Parse and process the receipt into the local database
        self.psr.parse_one(&msg).map_err(|e| {
            ValidationError(format!("Failed to process receipt into database: {}", e))
        })?;

        Ok(msg)
    }

    pub fn witness(&mut self, serder: &SerderKERI) -> Result<Vec<u8>, KERIError> {
        // Check if this habitat's identifier is transferable (witnesses must be non-transferable)
        let kever = self.kever()?;
        let prefixer = kever
            .prefixer
            .as_ref()
            .ok_or_else(|| ValidationError("Missing prefixer in kever".to_string()))?;

        if prefixer.transferable() {
            return Err(ValidationError(format!(
                "Attempt to create witness receipt with transferable pre={}",
                self.pre.as_deref().unwrap_or("unknown")
            )));
        }

        // Extract event details from the provided serder
        let ked = serder.ked();

        // Get the identifier prefix from the event being witnessed
        let event_pre = ked
            .get("i")
            .and_then(|v| match v {
                SadValue::String(s) => Some(s.clone()),
                _ => None,
            })
            .ok_or_else(|| ValidationError("Missing or invalid identifier in event".to_string()))?;

        // Check if we have key state for the event's identifier
        if !self.kvy.kevers.contains_key(&event_pre) {
            return Err(ValidationError(format!(
                "Attempt by {} to witness event with missing key state",
                self.pre.as_deref().unwrap_or("unknown")
            )));
        }

        // Get the kever for the event being witnessed
        let event_kever = self
            .kvy
            .kevers
            .get(&event_pre)
            .ok_or_else(|| MissingEntryError(format!("No kever for prefix {}", event_pre)))?;

        // Check if this habitat is in the witness list
        let witness_pre = self
            .pre
            .as_ref()
            .ok_or_else(|| ConfigurationError("No prefix set for habitat".to_string()))?;

        let witness_index = event_kever.wits().iter().position(|wit| wit == witness_pre);

        if witness_index.is_none() {
            println!(
                "Attempt by {} to witness event of {} when not a witness in wits={:?}",
                witness_pre,
                event_pre,
                event_kever.wits()
            );
        }

        let index = witness_index.unwrap_or(0); // Use 0 as fallback if not found

        // Get the sequence number from the event and convert from hex
        let sn_hex = ked
            .get("s")
            .and_then(|v| match v {
                SadValue::String(s) => Some(s.clone()),
                _ => None,
            })
            .ok_or_else(|| {
                ValidationError("Missing or invalid sequence number in event".to_string())
            })?;

        let sn = usize::from_str_radix(&sn_hex, 16)
            .map_err(|_| ValidationError("Invalid hex sequence number format".to_string()))?;

        // Get the SAID of the event
        let said = serder
            .said()
            .ok_or_else(|| ValidationError("Missing SAID in event serder".to_string()))?
            .to_string();

        // Create the receipt event using ReceiptEventBuilder
        let receipt_serder = ReceiptEventBuilder::new(event_pre, sn, said)
            .build()
            .map_err(|e| ValidationError(format!("Failed to build receipt event: {}", e)))?;

        // Since witness id is non-transferable, the public key is the same as the prefix
        // Create witness signatures using the manager's sign method
        let signatures = self.mgr.sign(
            &serder.raw(),                   // Sign the original event, not the receipt
            Some(vec![witness_pre.clone()]), // pubs: witness prefix as public key
            None,                            // verfers: not using verfers for witness
            Some(true),                      // indexed: create indexed signatures
            Some(vec![index as u32]),        // indices: witness index in the witness list
            None,                            // ondices: not applicable
            None,                            // pre: not using pre-based signing
            None,                            // path: not specified
        )?;

        // Extract Siger instances from Sigmat enum (witnesses use indexed signatures)
        let wigers: Result<Vec<Siger>, KERIError> = signatures
            .into_iter()
            .map(|sig| match sig {
                Sigmat::Indexed(siger) => Ok(siger),
                Sigmat::NonIndexed(_) => Err(KERIError::ValidationError(
                    "Expected Siger but got Cigar - indexed signatures required for witness"
                        .to_string(),
                )),
            })
            .collect();

        let wigers = wigers?;

        // Create the witness receipt message with receipt serder and witness signatures
        let msg = messagize(
            &receipt_serder, // serder: the receipt event
            None,            // sigers: not used for witness receipts
            None,            // seal: not used for witness receipts
            Some(&wigers),   // wigers: witness signatures
            None,            // cigars: not used for witness receipts
            true,            // pipelined: standard message format
        )
        .map_err(|e| ValidationError(format!("Failed to create witness receipt message: {}", e)))?;

        // Process local copy into database
        self.psr.parse_one(&mut msg.clone())?;

        Ok(msg)
    }
    /// Replay events for the given prefix starting from the specified first seen number.
    ///
    /// This method creates a complete replay by first including the delegation chain
    /// (if the identifier is delegated), then including all events for the prefix
    /// starting from the specified first seen ordinal number.
    ///
    /// # Parameters
    /// * `pre` - Optional identifier prefix as string. If None, uses self.pre
    /// * `fn_num` - Optional first seen number to start replay from. Default is 0
    ///
    /// # Returns
    /// * `Result<Vec<u8>, KERIError>` - Concatenated messages representing the complete replay
    pub fn replay(&self, pre: Option<&str>, fn_num: Option<u64>) -> Result<Vec<u8>, KERIError> {
        // Use provided prefix or default to self.pre
        let replay_pre = if let Some(p) = pre {
            p.to_string()
        } else {
            self.pre
                .as_ref()
                .ok_or_else(|| {
                    KERIError::ConfigurationError("No prefix set for habitat".to_string())
                })?
                .clone()
        };

        let fn_start = fn_num.unwrap_or(0);
        let mut msgs = Vec::new();

        // Get the kever for the prefix we're replaying
        let kever = self.kvy.kevers.get(&replay_pre).ok_or_else(|| {
            KERIError::MissingEntryError(format!("No kever for prefix {}", replay_pre))
        })?;

        // First clone the delegation chain if this is a delegated identifier
        let delegation_msgs = self
            .db
            .clone_delegation(kever)
            .map_err(|e| KERIError::DatabaseError(format!("Failed to clone delegation: {}", e)))?;

        for msg in delegation_msgs {
            msgs.extend(msg);
        }

        // Then clone all events for this prefix starting from fn
        let prefix_msgs = self
            .db
            .clone_pre_iter(&replay_pre, Some(fn_start))
            .map_err(|e| {
                KERIError::DatabaseError(format!("Failed to clone prefix events: {}", e))
            })?;

        for msg in prefix_msgs {
            msgs.extend(msg);
        }

        Ok(msgs)
    }

    /// Replay all events for all identifier prefixes in the database.
    ///
    /// This method creates a complete replay of all events across all prefixes
    /// in first seen order with attachments. Useful for database synchronization
    /// and backup scenarios.
    ///
    /// # Returns
    /// * `Result<Vec<u8>, KERIError>` - Concatenated messages representing all events
    pub fn replay_all(&self) -> Result<Vec<u8>, KERIError> {
        let mut msgs = Vec::new();

        // Get all event messages from the database
        let all_msgs = self
            .db
            .clone_all_pre_iter()
            .map_err(|e| KERIError::DatabaseError(format!("Failed to clone all events: {}", e)))?;

        // Concatenate all messages
        for msg in all_msgs {
            msgs.extend(msg);
        }

        Ok(msgs)
    }
    /// Make other event message for given prefix and sequence number.
    ///
    /// # Parameters
    /// * `pre` - The prefix identifier
    /// * `sn` - The sequence number
    ///
    /// # Returns
    /// * `Ok(Some(Vec<u8>))` - The event message bytes if found
    /// * `Ok(None)` - If prefix not in kevers
    /// * `Err(KERIError)` - If missing event or other error
    pub fn make_other_event(
        &self,
        pre: impl AsRef<[u8]>,
        sn: u64,
    ) -> Result<Option<Vec<u8>>, KERIError> {
        let pre_bytes = pre.as_ref();

        // Convert bytes to string for kevers lookup
        let pre_str = String::from_utf8_lossy(pre_bytes);

        // Check if prefix exists in kevers
        if !self.kevers().contains_key(pre_str.as_ref()) {
            return Ok(None);
        }

        let mut msg = Vec::<u8>::new();

        // Get the last digest for this prefix and sequence number
        let sn_key = sn_key(pre_bytes, sn);
        let dig = match self.db.get_ke_last(&sn_key)? {
            Some(digest) => digest,
            None => {
                return Err(KERIError::MissingEntryError(format!(
                    "Missing event for pre={} at sn={}",
                    pre_str, sn
                )));
            }
        };

        // Create digest key and get event
        let key = dg_key(pre_bytes, dig.as_bytes());
        let evt = match self.db.get_evt(&key)? {
            Some(event) => event,
            None => {
                return Err(KERIError::MissingEntryError(format!(
                    "Missing event data for key"
                )));
            }
        };
        msg.extend_from_slice(&evt);

        // Get signature count and create counter
        let sig_count = self.db.cnt_sigs(&key)?;
        let base_counter = BaseCounter::from_code_and_count(
            Some(ctr_dex_1_0::CONTROLLER_IDX_SIGS),
            Some(sig_count as u64),
            None,
        )
        .map_err(|e| KERIError::CounterError(format!("Failed to create counter: {}", e)))?;

        // Use as Counter trait and get qb64 bytes
        let counter: &dyn Counter = &base_counter;
        let counter_bytes = counter.qb64b();
        msg.extend_from_slice(&counter_bytes);

        // Attach all signatures
        for sig_result in self.db.get_sigs_iter(&key)? {
            let sig = sig_result?;
            msg.extend_from_slice(&sig);
        }

        Ok(Some(msg))
    }
    /// Fetch endpoint record for given cid, role, and eid
    ///
    /// # Parameters
    /// * `cid` - Controller identifier (qb64 prefix)
    /// * `role` - Role such as watcher, witness
    /// * `eid` - Endpoint identifier
    ///
    /// # Returns
    /// * `Ok(Some(EndpointRecord))` - If record found
    /// * `Ok(None)` - If no record found
    /// * `Err(KERIError)` - On database error
    pub fn fetch_end(
        &self,
        cid: &str,
        role: &str,
        eid: &str,
    ) -> Result<Option<EndpointRecord>, KERIError> {
        let keys = [cid.as_bytes(), role.as_bytes(), eid.as_bytes()];
        self.db.ends.get(&keys).map_err(|e| {
            KERIError::DatabaseError(format!("Failed to fetch endpoint record: {}", e))
        })
    }

    /// Fetch location record for given eid and scheme
    ///
    /// # Parameters
    /// * `eid` - Endpoint identifier
    /// * `scheme` - URL protocol scheme (defaults to "http")
    ///
    /// # Returns
    /// * `Ok(Some(LocationRecord))` - If record found
    /// * `Ok(None)` - If no record found
    /// * `Err(KERIError)` - On database error
    pub fn fetch_loc(
        &self,
        eid: &str,
        scheme: Option<&str>,
    ) -> Result<Option<LocationRecord>, KERIError> {
        let scheme = scheme.unwrap_or("http"); // Default to HTTP scheme
        let keys = [eid.as_bytes(), scheme.as_bytes()];
        self.db.locs.get(&keys).map_err(|e| {
            KERIError::DatabaseError(format!("Failed to fetch location record: {}", e))
        })
    }

    /// Fetch endpoint allowed status for given cid, role, and eid
    ///
    /// # Parameters
    /// * `cid` - Controller identifier (qb64 prefix)
    /// * `role` - Role such as watcher, witness
    /// * `eid` - Endpoint identifier
    ///
    /// # Returns
    /// * `Ok(Some(bool))` - If record found and allowed status is set
    /// * `Ok(None)` - If no record found or allowed status is None
    /// * `Err(KERIError)` - On database error
    pub fn fetch_end_allowed(
        &self,
        cid: &str,
        role: &str,
        eid: &str,
    ) -> Result<Option<bool>, KERIError> {
        match self.fetch_end(cid, role, eid)? {
            Some(end) => Ok(end.allowed),
            None => Ok(None),
        }
    }

    /// Fetch endpoint enabled status for given cid, role, and eid
    ///
    /// # Parameters
    /// * `cid` - Controller identifier (qb64 prefix)
    /// * `role` - Role such as watcher, witness
    /// * `eid` - Endpoint identifier
    ///
    /// # Returns
    /// * `Ok(Some(bool))` - If record found and enabled status is set
    /// * `Ok(None)` - If no record found or enabled status is None
    /// * `Err(KERIError)` - On database error
    pub fn fetch_end_enabled(
        &self,
        cid: &str,
        role: &str,
        eid: &str,
    ) -> Result<Option<bool>, KERIError> {
        match self.fetch_end(cid, role, eid)? {
            Some(end) => Ok(end.enabled),
            None => Ok(None),
        }
    }

    /// Fetch endpoint authorization status (enabled OR allowed) for given cid, role, and eid
    ///
    /// # Parameters
    /// * `cid` - Controller identifier (qb64 prefix)
    /// * `role` - Role such as watcher, witness
    /// * `eid` - Endpoint identifier
    ///
    /// # Returns
    /// * `Ok(Some(bool))` - If record found and either enabled or allowed is true
    /// * `Ok(None)` - If no record found or both enabled and allowed are None/false
    /// * `Err(KERIError)` - On database error
    pub fn fetch_end_authzed(
        &self,
        cid: &str,
        role: &str,
        eid: &str,
    ) -> Result<Option<bool>, KERIError> {
        match self.fetch_end(cid, role, eid)? {
            Some(end) => {
                let authorized = end.enabled.unwrap_or(false) || end.allowed.unwrap_or(false);
                if authorized {
                    Ok(Some(true))
                } else {
                    // Return None if both are None or false
                    if end.enabled.is_none() && end.allowed.is_none() {
                        Ok(None)
                    } else {
                        Ok(Some(false))
                    }
                }
            }
            None => Ok(None),
        }
    }

    /// Fetch URL for given eid and scheme
    ///
    /// # Parameters
    /// * `eid` - Endpoint identifier
    /// * `scheme` - URL protocol scheme (defaults to "http")
    ///
    /// # Returns
    /// * `Ok(Some(String))` - If location record found, returns the URL
    /// * `Ok(None)` - If no location record found
    /// * `Err(KERIError)` - On database error
    pub fn fetch_url(&self, eid: &str, scheme: Option<&str>) -> Result<Option<String>, KERIError> {
        match self.fetch_loc(eid, scheme)? {
            Some(loc) => Ok(Some(loc.url)),
            None => Ok(None),
        }
    }

    /// Fetch URLs for given eid and optional scheme filter
    /// Returns a Mict containing (scheme, url) pairs for all matching locations
    ///
    /// # Parameters
    /// * `eid` - Endpoint identifier
    /// * `scheme` - Optional scheme filter (empty string means all schemes)
    ///
    /// # Returns
    /// * `Ok(Mict<String, String>)` - Mict containing scheme->url mappings
    /// * `Err(KERIError)` - On database error
    pub fn fetch_urls(
        &self,
        eid: &str,
        scheme: Option<&str>,
    ) -> Result<Mict<String, String>, KERIError> {
        let scheme_filter = scheme.unwrap_or("");

        // Get vector of location records matching the eid and scheme pattern
        let items = self
            .db
            .locs
            .get_item_iter(&[eid.as_bytes(), scheme_filter.as_bytes()])
            .map_err(|e| {
                KERIError::DatabaseError(format!("Failed to get location items: {}", e))
            })?;

        // Filter and transform the items using into_iter()
        let url_pairs: Vec<(String, String)> = items
            .into_iter()
            .filter_map(|(keys, loc)| {
                // Only include locations with non-empty URLs
                if !loc.url.is_empty() && keys.len() >= 2 {
                    // Extract scheme from keys[1] and pair with URL
                    Some((keys[1].clone(), loc.url))
                } else {
                    None
                }
            })
            .collect();

        Ok(Mict::from_iter(url_pairs))
    }

    /// Fetch role URLs for given cid, role, and optional filters
    /// Returns a Mict containing role -> Mict(eid -> urls) mappings
    ///
    /// # Parameters
    /// * `cid` - Controller identifier
    /// * `role` - Optional role filter (empty string means all roles)
    /// * `scheme` - Optional scheme filter (empty string means all schemes)
    /// * `eids` - Optional list of endpoint identifiers to filter by
    /// * `enabled` - Whether to include enabled endpoints
    /// * `allowed` - Whether to include allowed endpoints
    ///
    /// # Returns
    /// * `Ok(Mict<String, Mict<String, Mict<String, String>>>)` - Nested Mict structure
    /// * `Err(KERIError)` - On database error
    pub fn fetch_role_urls(
        &self,
        cid: &str,
        role: Option<&str>,
        scheme: Option<&str>,
        eids: Option<&[String]>,
        enabled: bool,
        allowed: bool,
    ) -> Result<Mict<String, Mict<String, Mict<String, String>>>, KERIError> {
        let role_filter = role.unwrap_or("");
        let mut rurls = Mict::new();

        // Special handling for witness role - get from kever's witness list
        if role_filter == Roles::Witness.as_str() || role_filter.is_empty() {
            if let Some(kever) = self.kevers().get(cid) {
                // Latest key state for cid - iterate through witnesses
                for wit in &kever.wits {
                    // Convert Vec<String> to a single string (assuming it's a prefix or identifier)
                    let eid = wit.join(""); // or wit[0] if you only need the first element

                    if eids.is_none() || eids.unwrap().contains(&eid) {
                        let surls = self.fetch_urls(&eid, scheme)?;
                        if !surls.is_empty() {
                            let mut eid_urls = Mict::new();
                            eid_urls.add(eid.clone(), surls);
                            rurls.add(Roles::Witness.as_str().to_string(), eid_urls);
                        }
                    }
                }
            }
        }

        // Get endpoints from database
        let items = self
            .db
            .ends
            .get_item_iter(&[cid.as_bytes(), role_filter.as_bytes()])
            .map_err(|e| {
                KERIError::DatabaseError(format!("Failed to get endpoint items: {}", e))
            })?;

        for (keys, end) in items {
            // Check authorization (enabled or allowed as requested)
            let is_authorized = (enabled && end.enabled.unwrap_or(false))
                || (allowed && end.allowed.unwrap_or(false));

            if is_authorized && keys.len() >= 3 {
                let erole = &keys[1]; // role from database key
                let eid = &keys[2]; // eid from database key

                // Filter by eids if provided
                if eids.is_none() || eids.unwrap().contains(eid) {
                    let surls = self.fetch_urls(eid, scheme)?;
                    if !surls.is_empty() {
                        let mut eid_urls = Mict::new();
                        eid_urls.add(eid.clone(), surls);
                        rurls.add(erole.clone(), eid_urls);
                    }
                }
            }
        }

        Ok(rurls)
    }

    /// Fetch witness URLs for given cid
    /// Convenience method that calls fetch_role_urls with witness role
    ///
    /// # Parameters
    /// * `cid` - Controller identifier
    /// * `scheme` - Optional scheme filter (empty string means all schemes)
    /// * `eids` - Optional list of endpoint identifiers to filter by
    /// * `enabled` - Whether to include enabled endpoints
    /// * `allowed` - Whether to include allowed endpoints
    ///
    /// # Returns
    /// * `Ok(Mict<String, Mict<String, Mict<String, String>>>)` - Nested Mict structure
    /// * `Err(KERIError)` - On database error
    pub fn fetch_witness_urls(
        &self,
        cid: &str,
        scheme: Option<&str>,
        eids: Option<&[String]>,
        enabled: bool,
        allowed: bool,
    ) -> Result<Mict<String, Mict<String, Mict<String, String>>>, KERIError> {
        self.fetch_role_urls(
            cid,
            Some(Roles::Witness.as_str()),
            scheme,
            eids,
            enabled,
            allowed,
        )
    }

    /// Get all endpoints for a given prefix, organized by role and endpoint ID
    /// Returns a nested HashMap structure: role -> eid -> scheme -> url
    ///
    /// # Parameters
    /// * `pre` - Prefix (controller identifier)
    ///
    /// # Returns
    /// * `Ok(HashMap<String, HashMap<String, HashMap<String, String>>>)` - Nested structure of endpoints
    /// * `Err(KERIError)` - On database error
    pub fn ends_for(
        &self,
        pre: &str,
    ) -> Result<HashMap<String, HashMap<String, HashMap<String, String>>>, KERIError> {
        let mut ends: HashMap<String, HashMap<String, HashMap<String, String>>> = HashMap::new();

        // Get all endpoints from database for the given prefix
        let items = self.db.ends.get_item_iter(&[pre.as_bytes()]).map_err(|e| {
            KERIError::DatabaseError(format!("Failed to get endpoint items: {}", e))
        })?;

        for (keys, end) in items {
            if keys.len() >= 3 {
                let erole = &keys[1]; // role from database key
                let eid = &keys[2]; // eid from database key

                // Fetch URLs for this endpoint
                let urls = self.fetch_urls(eid, None)?;

                // Convert URLs to HashMap using firsts() method
                let mut locs: HashMap<String, String> = HashMap::new();
                for (rscheme, url) in urls.firsts() {
                    locs.insert(rscheme, url);
                }

                // Initialize role entry if it doesn't exist
                if !ends.contains_key(erole) {
                    ends.insert(erole.clone(), HashMap::new());
                }

                // Add the location mapping for this endpoint
                ends.get_mut(erole).unwrap().insert(eid.clone(), locs);
            }
        }

        // Handle witness endpoints separately from kever
        let mut witrolls: HashMap<String, HashMap<String, String>> = HashMap::new();

        if let Some(kever) = self.kevers().get(pre) {
            let witness_ids = kever.wits();

            for eid in witness_ids {
                // Fetch URLs for this witness endpoint
                let urls = self.fetch_urls(&eid, None)?;

                // Convert URLs to HashMap using firsts() method
                let mut locs: HashMap<String, String> = HashMap::new();
                for (rscheme, url) in urls.firsts() {
                    locs.insert(rscheme, url);
                }

                witrolls.insert(eid, locs);
            }
        }

        // Add witness endpoints if any exist
        if !witrolls.is_empty() {
            ends.insert(Roles::Witness.as_str().to_string(), witrolls);
        }

        Ok(ends)
    }

    /// Create and endorse a reply event
    ///
    /// # Parameters
    /// * `route` - Namespaced path that indicates data flow handler
    /// * `data` - Optional attribute section of reply
    /// * `stamp` - Optional timestamp (RFC-3339 format)
    /// * `version` - Optional version string
    /// * `kind` - Optional serialization kind
    /// * `last` - Optional flag for seal type (default: false)
    /// * `pipelined` - Optional flag for message format (default: true)
    ///
    /// # Returns
    /// * `Ok(Vec<u8>)` - Endorsed reply message
    /// * `Err(KERIError)` - On validation or signing error
    pub fn reply(
        &self,
        route: String,
        data: Option<IndexMap<String, SadValue>>,
        stamp: Option<String>,
        version: Option<String>,
        kind: Option<String>,
        last: Option<bool>,
        pipelined: Option<bool>,
    ) -> Result<Vec<u8>, KERIError> {
        // Build the reply event using ReplyEventBuilder
        let mut builder = ReplyEventBuilder::new().with_route(route);

        if let Some(data) = data {
            builder = builder.with_data(data);
        }

        if let Some(stamp) = stamp {
            builder = builder.with_stamp(stamp);
        }

        if let Some(version) = version {
            builder = builder.with_version(version);
        }

        if let Some(kind) = kind {
            builder = builder.with_kind(kind);
        }

        // Build the serder
        let serder = builder.build()?;

        // Endorse the reply event
        self.endorse(&serder, last, pipelined)
    }

    /// Create and endorse an endpoint role management reply event
    ///
    /// # Parameters
    /// * `eid` - Endpoint identifier
    /// * `role` - Role to assign (default: Controller)
    /// * `allow` - If true, adds the role; if false, removes it (default: true)
    /// * `stamp` - Optional timestamp (RFC-3339 format)
    ///
    /// # Returns
    /// * `Ok(Vec<u8>)` - Endorsed endpoint role reply message
    /// * `Err(KERIError)` - On validation or signing error
    pub fn make_end_role(
        &self,
        eid: String,
        role: Option<Roles>,
        allow: Option<bool>,
        stamp: Option<String>,
    ) -> Result<Vec<u8>, KERIError> {
        let role = role.unwrap_or(Roles::Controller);
        let allow = allow.unwrap_or(true);

        // Get the habitat's prefix
        let pre = self
            .pre
            .as_ref()
            .ok_or_else(|| KERIError::ValidationError("Missing habitat prefix".to_string()))?;

        // Create data payload
        let mut data = IndexMap::new();
        data.insert("cid".to_string(), SadValue::String(pre.clone()));
        data.insert(
            "role".to_string(),
            SadValue::String(role.as_str().to_string()),
        );
        data.insert("eid".to_string(), SadValue::String(eid));

        // Determine route based on allow flag
        let route = if allow {
            "/end/role/add".to_string()
        } else {
            "/end/role/cut".to_string()
        };

        // Create and endorse the reply
        self.reply(route, Some(data), stamp, None, None, None, None)
    }

    /// Load and reconstruct an endpoint role message from the database
    ///
    /// # Parameters
    /// * `cid` - Controller identifier
    /// * `eid` - Endpoint identifier  
    /// * `role` - Role to load (default: Controller)
    ///
    /// # Returns
    /// * `Ok(Vec<u8>)` - Reconstructed message bytes
    /// * `Err(KERIError)` - On database error or validation failure
    pub fn load_end_role(
        &self,
        cid: &str,
        eid: &str,
        role: Option<Roles>,
    ) -> Result<Vec<u8>, KERIError> {
        let role = role.unwrap_or(Roles::Controller);
        let mut msgs = Vec::new();

        // Check if endpoint exists and is enabled/allowed
        let end = self
            .db
            .ends
            .get(&[cid.as_bytes(), role.as_str().as_bytes(), eid.as_bytes()])
            .map_err(|e| KERIError::DatabaseError(format!("Failed to get endpoint: {}", e)))?;

        if let Some(end) = end {
            // Fix: Handle Option<bool> properly - default to false if None
            if end.enabled.unwrap_or(false) || end.allowed.unwrap_or(false) {
                // Get the SAID for this endpoint role
                let said = self
                    .db
                    .eans
                    .get(&[cid.as_bytes(), role.as_str().as_bytes(), eid.as_bytes()])
                    .map_err(|e| KERIError::DatabaseError(format!("Failed to get SAID: {}", e)))?;

                if let Some(said) = said {
                    // Get the reply serder
                    let serder = self.db.rpys.get(&[said.qb64().as_bytes()]).map_err(|e| {
                        KERIError::DatabaseError(format!("Failed to get reply: {}", e))
                    })?;

                    if let Some(serder) = serder {
                        // Get cigars (non-transferable signatures)
                        let cigars_result =
                            self.db.scgs.get(&[said.qb64().as_bytes()]).map_err(|e| {
                                KERIError::DatabaseError(format!("Failed to get cigars: {}", e))
                            })?;

                        // Get transferable signature groups
                        let tsgs = self.db.fetch_tsgs(said, None)?;

                        // Process cigars
                        let cigar = if cigars_result.len() == 1 && cigars_result[0].len() == 2 {
                            // Extract verfer and cigar from the pair
                            let verfer_matter = &cigars_result[0][0];
                            let cigar_matter = &cigars_result[0][1];

                            // Fix: Handle Option types from downcast_ref properly
                            if let (Some(verfer), Some(cigar)) = (
                                verfer_matter.as_any().downcast_ref::<Verfer>(),
                                cigar_matter.as_any().downcast_ref::<Cigar>(),
                            ) {
                                // Create a mutable clone and set the verfer
                                let mut cigar_clone = cigar.clone();
                                cigar_clone.set_verfer(verfer.clone());
                                Some(cigar_clone)
                            } else {
                                None
                            }
                        } else {
                            None
                        };

                        // Process transferable signature groups
                        let (sigers, seal) = if !tsgs.is_empty() {
                            let (prefixer, seqner, diger, sigers) = &tsgs[0];

                            let seal = SealEvent::new(prefixer.qb64(), seqner.snh(), diger.qb64());

                            (Some(sigers.as_slice()), Some(Seal::SealEvent(seal)))
                        } else {
                            (None, None)
                        };

                        // Create the message
                        let cigars_slice: Option<&[Cigar]> = if let Some(ref cigar) = cigar {
                            // Fix: Provide explicit type annotation for the slice
                            Some(std::slice::from_ref(cigar))
                        } else {
                            None
                        };

                        let msg = messagize(
                            &serder,
                            sigers,
                            seal,
                            None, // wigers
                            cigars_slice,
                            true, // pipelined
                        )
                        .map_err(|e| {
                            KERIError::ValidationError(format!("Failed to create message: {}", e))
                        })?;

                        msgs.extend(msg);
                    }
                }
            }
        }

        Ok(msgs)
    }

    /// Create and endorse a location scheme reply message
    ///
    /// # Parameters
    /// * `url` - The URL for this location scheme
    /// * `eid` - Optional endpoint identifier (defaults to self.pre)
    /// * `scheme` - Scheme type (default: "http")
    /// * `stamp` - Optional timestamp (RFC-3339 format)
    ///
    /// # Returns
    /// * `Ok(Vec<u8>)` - Endorsed location scheme reply message
    /// * `Err(KERIError)` - On validation or signing error
    pub fn make_loc_scheme(
        &self,
        url: String,
        eid: Option<String>,
        scheme: Option<String>,
        stamp: Option<String>,
    ) -> Result<Vec<u8>, KERIError> {
        let eid = match eid {
            Some(eid) => eid,
            None => self.pre.clone().ok_or_else(|| {
                KERIError::ValueError("No pre available for default eid".to_string())
            })?,
        };

        let scheme = scheme.unwrap_or_else(|| "http".to_string());

        // Create the data payload
        let mut data = IndexMap::new();
        data.insert("eid".to_string(), SadValue::String(eid));
        data.insert("scheme".to_string(), SadValue::String(scheme));
        data.insert("url".to_string(), SadValue::String(url));

        // Create the reply message
        self.reply(
            "/loc/scheme".to_string(),
            Some(data),
            stamp,
            None, // version
            None, // kind
            None, // last
            None, // pipelined
        )
    }

    /// Create reply messages for all location schemes matching the given eid and scheme
    ///
    /// # Parameters
    /// * `eid` - Endpoint identifier
    /// * `scheme` - Optional scheme filter (empty string means all schemes)
    ///
    /// # Returns
    /// * `Ok(Vec<u8>)` - Combined reply messages for all matching location schemes
    /// * `Err(KERIError)` - On database error or message creation failure
    pub fn reply_loc_scheme(
        &self,
        eid: String,
        scheme: Option<String>,
    ) -> Result<Vec<u8>, KERIError> {
        let mut msgs = Vec::new();
        let scheme_filter = scheme.as_deref().unwrap_or("");

        // Fetch URLs for the given eid and scheme
        let urls = self.fetch_urls(&eid, Some(scheme_filter))?;

        // Iterate over the first occurrence of each scheme-url pair
        for (rscheme, url) in urls.firsts() {
            let scheme_msg = self.make_loc_scheme(
                url.clone(),
                Some(eid.clone()),
                Some(rscheme.clone()),
                None, // stamp
            )?;
            msgs.extend(scheme_msg);
        }

        Ok(msgs)
    }

    /// Load and reconstruct location scheme messages from the database
    ///
    /// # Parameters
    /// * `eid` - Endpoint identifier
    /// * `scheme` - Optional scheme filter (None means all schemes)
    ///
    /// # Returns
    /// * `Ok(Vec<u8>)` - Reconstructed message bytes
    /// * `Err(KERIError)` - On database error or validation failure
    pub fn load_loc_scheme(&self, eid: &str, scheme: Option<&str>) -> Result<Vec<u8>, KERIError> {
        let mut msgs = Vec::new();

        // Build keys based on whether scheme is provided
        let keys: Vec<&[u8]> = if let Some(scheme) = scheme {
            vec![eid.as_bytes(), scheme.as_bytes()]
        } else {
            vec![eid.as_bytes()]
        };

        // Get items from lans database
        let items = self.db.lans.get_item_iter(&keys, false).map_err(|e| {
            KERIError::DatabaseError(format!("Failed to get location items: {}", e))
        })?;

        for (pre_keys, said_bytes) in items {
            // Convert said_bytes to Saider
            let said = Saider::from_qb64(&String::from_utf8_lossy(&said_bytes))
                .map_err(|e| KERIError::ValidationError(format!("Invalid SAID: {}", e)))?;

            // Get the reply serder
            let serder = self
                .db
                .rpys
                .get(&[said.qb64().as_bytes()])
                .map_err(|e| KERIError::DatabaseError(format!("Failed to get reply: {}", e)))?;

            if let Some(serder) = serder {
                // Get cigars (non-transferable signatures)
                let cigars_result = self.db.scgs.get(&[said.qb64().as_bytes()]).map_err(|e| {
                    KERIError::DatabaseError(format!("Failed to get cigars: {}", e))
                })?;

                // Get transferable signature groups
                let tsgs = self.db.fetch_tsgs(said, None)?;

                // Process cigars
                let cigar = if cigars_result.len() == 1 && cigars_result[0].len() == 2 {
                    // Extract verfer and cigar from the pair
                    let verfer_matter = &cigars_result[0][0];
                    let cigar_matter = &cigars_result[0][1];

                    // Convert Matter to appropriate types
                    if let (Some(verfer), Some(cigar)) = (
                        verfer_matter.as_any().downcast_ref::<Verfer>(),
                        cigar_matter.as_any().downcast_ref::<Cigar>(),
                    ) {
                        // Create a mutable clone and set the verfer
                        let mut cigar_clone = cigar.clone();
                        cigar_clone.set_verfer(verfer.clone());
                        Some(cigar_clone)
                    } else {
                        None
                    }
                } else {
                    None
                };

                // Process transferable signature groups
                let (sigers, seal) = if !tsgs.is_empty() {
                    let (prefixer, seqner, diger, sigers) = &tsgs[0];

                    let seal = SealEvent::new(prefixer.qb64(), seqner.snh(), diger.qb64());

                    (Some(sigers.as_slice()), Some(Seal::SealEvent(seal)))
                } else {
                    (None, None)
                };

                // Create the message
                let cigars_slice: Option<&[Cigar]> = if let Some(ref cigar) = cigar {
                    Some(std::slice::from_ref(cigar))
                } else {
                    None
                };

                let msg = messagize(
                    &serder,
                    sigers,
                    seal,
                    None, // wigers
                    cigars_slice,
                    true, // pipelined
                )
                .map_err(|e| {
                    KERIError::ValidationError(format!("Failed to create message: {}", e))
                })?;

                msgs.extend(msg);
            }
        }

        Ok(msgs)
    }

    /// Reply with endpoint role information for a given controller identifier
    ///
    /// # Parameters
    /// * `cid` - Controller identifier
    /// * `role` - Optional role filter (None means all roles)
    /// * `eids` - Optional list of endpoint identifiers to filter by
    /// * `scheme` - Scheme filter for location queries (empty string means all schemes)
    ///
    /// # Returns
    /// * `Ok(Vec<u8>)` - Combined reply messages
    /// * `Err(KERIError)` - On database error or validation failure
    pub fn reply_end_role(
        &self,
        cid: &str,
        role: Option<Roles>,
        eids: Option<&[String]>,
        scheme: Option<&str>,
    ) -> Result<Vec<u8>, KERIError> {
        let mut msgs = Vec::new();
        let scheme_filter = scheme.unwrap_or("");

        // Check if we have a kever for this cid
        let kevers = self.kevers();
        if !kevers.contains_key(cid) {
            return Ok(msgs); // Return empty messages if no kever found
        }

        // Replay events for this cid
        let replay_msgs = self.replay(Some(cid), None)?;
        msgs.extend(replay_msgs);

        let kever = &kevers[cid];
        let kever_wits = kever.wits();

        // Check if we are a witness for this cid
        let witness = if let Some(self_pre) = &self.pre {
            kever_wits.contains(self_pre)
        } else {
            false
        };

        // Handle witness role specifically
        if let Some(Roles::Witness) = role {
            // Process all witnesses for this cid
            for eid in &kever_wits {
                // Check if we should include this eid
                let should_include = if let Some(eids_filter) = eids {
                    eids_filter.contains(eid)
                } else {
                    true
                };

                if should_include {
                    // If this is our own endpoint, reply with location scheme
                    if let Some(self_pre) = &self.pre {
                        if eid == self_pre {
                            let loc_msgs = self.reply_loc_scheme(
                                eid.clone(),
                                if scheme_filter.is_empty() {
                                    None
                                } else {
                                    Some(scheme_filter.to_string())
                                },
                            )?;
                            msgs.extend(loc_msgs);
                        } else {
                            // Load location scheme for other witnesses
                            let loc_msgs = self.load_loc_scheme(eid, Some(scheme_filter))?;
                            msgs.extend(loc_msgs);
                        }
                    } else {
                        // Load location scheme for all witnesses if we don't have a pre
                        let loc_msgs = self.load_loc_scheme(eid, Some(scheme_filter))?;
                        msgs.extend(loc_msgs);
                    }

                    // If we are not a witness, send auth records
                    if !witness {
                        let auth_msgs = self.make_end_role(
                            eid.clone(),
                            Some(Roles::Witness),
                            None, // allow (default: true)
                            None, // stamp
                        )?;
                        msgs.extend(auth_msgs);
                    }
                }
            }
        }

        // Process all endpoint roles from the database
        let items = self.db.ends.get_item_iter(&[cid.as_bytes()]).map_err(|e| {
            KERIError::DatabaseError(format!("Failed to get endpoint items: {}", e))
        })?;

        for (keys, end) in items {
            // Keys should be [cid, role, eid] - we need at least role and eid
            if keys.len() >= 2 {
                let erole_str = &keys[0]; // role is first key after cid
                let eid = &keys[1]; // eid is second key after cid

                // Parse the role string
                let erole = match Roles::from_str(erole_str) {
                    Ok(r) => r,
                    Err(_) => continue, // Skip invalid roles
                };

                // Check if this endpoint should be included
                let enabled_or_allowed =
                    end.enabled.unwrap_or(false) || end.allowed.unwrap_or(false);
                let role_matches = role.is_none() || role == Some(erole);
                let eid_matches = eids.is_none() || eids.unwrap().contains(eid);

                if enabled_or_allowed && role_matches && eid_matches {
                    // Load location scheme for this endpoint
                    let loc_msgs = self.load_loc_scheme(eid, Some(scheme_filter))?;
                    msgs.extend(loc_msgs);

                    // Load endpoint role information
                    let role_msgs = self.load_end_role(cid, eid, Some(erole))?;
                    msgs.extend(role_msgs);
                }
            }
        }

        Ok(msgs)
    }

    /// Reply to OOBI (Out-Of-Band Introduction) request
    /// This is a simple wrapper around reply_end_role
    ///
    /// # Parameters
    /// * `aid` - Agent identifier (controller ID)
    /// * `role` - Role to reply with
    /// * `eids` - Optional list of endpoint identifiers to filter by
    ///
    /// # Returns
    /// * `Ok(Vec<u8>)` - Combined reply messages
    /// * `Err(KERIError)` - On database error or validation failure
    pub fn reply_to_oobi(
        &self,
        aid: &str,
        role: Roles,
        eids: Option<&[String]>,
    ) -> Result<Vec<u8>, KERIError> {
        self.reply_end_role(aid, Some(role), eids, None)
    }

    /// Get own event at specified sequence number
    ///
    /// # Parameters
    /// * `sn` - Sequence number of the event to retrieve
    /// * `allow_partially_signed` - If true, also check partially signed events database
    ///
    /// # Returns
    /// * `Ok((SerderKERI, Vec<Siger>, Option<T>))` - Event serder, signatures, and optional couple
    /// * `Err(KERIError)` - On missing event or database error
    pub fn get_own_event<T>(
        &self,
        sn: u64,
        allow_partially_signed: bool,
    ) -> Result<(SerderKERI, Vec<Siger>, Option<T>), KERIError>
    where
        T: TryFrom<Vec<u8>>,
        <T as TryFrom<Vec<u8>>>::Error: std::fmt::Debug,
    {
        // Get our prefix
        let pre = self
            .pre
            .as_ref()
            .ok_or_else(|| KERIError::ValidationError("Missing habitat prefix".to_string()))?;

        // Create sequence number key
        let key = sn_key(pre, sn);

        // Try to get digest from key event log
        let mut dig = self.db.get_ke_last(key.clone())?;

        // If not found and partially signed events are allowed, try PSE database
        if dig.is_none() && allow_partially_signed {
            let pse_result = self
                .db
                .pses
                .get_last::<_, Vec<u8>>(&[&key])
                .map_err(|e| KERIError::DatabaseError(format!("Failed to get PSE: {}", e)))?;

            if let Some(bytes) = pse_result {
                dig = Some(String::from_utf8(bytes).map_err(|e| {
                    KERIError::DeserializationError(format!(
                        "Failed to decode PSE digest as UTF-8: {}",
                        e
                    ))
                })?);
            }
        }

        // If still no digest found, return error
        let digest = dig.ok_or_else(|| {
            KERIError::MissingEntryError(format!("Missing event for pre={} at sn={}", pre, sn))
        })?;

        // Create digest key
        let dig_key = dg_key(pre, digest.as_bytes());

        // Get the event message
        let msg = self.db.get_evt(dig_key.clone())?.ok_or_else(|| {
            KERIError::MissingEntryError(format!("Missing event message for digest key"))
        })?;

        // Create serder from the raw message
        let serder = SerderKERI::from_raw(&msg, None)?;

        // Get signatures for this event
        let sigs_iter = self
            .db
            .sigs
            .get_iter::<_, Vec<u8>>(&[&dig_key])
            .map_err(|e| KERIError::DatabaseError(format!("Failed to get signatures: {}", e)))?;

        let mut sigs = Vec::new();
        for sig_result in sigs_iter {
            let mut sig_bytes = sig_result.map_err(|e| {
                KERIError::DatabaseError(format!("Failed to deserialize signature: {}", e))
            })?;

            let siger = Siger::from_qb64b(&mut sig_bytes, None).map_err(|e| {
                KERIError::ValidationError(format!("Failed to create Siger: {}", e))
            })?;

            sigs.push(siger);
        }

        // Get the couple (attachment anchor seal)
        let couple = self
            .db
            .aess
            .get::<_, T>(&[&dig_key])
            .map_err(|e| KERIError::DatabaseError(format!("Failed to get couple: {}", e)))?;

        Ok((serder, sigs, couple))
    }

    /// Create own event message with attachments at specified sequence number
    ///
    /// # Parameters
    /// * `sn` - Sequence number of the event to retrieve
    /// * `allow_partially_signed` - If true, also check partially signed events database
    ///
    /// # Returns
    /// * `Ok(Vec<u8>)` - Complete event message with attachments
    /// * `Err(KERIError)` - On missing event or database error
    pub fn make_own_event(
        &self,
        sn: u64,
        allow_partially_signed: bool,
    ) -> Result<Vec<u8>, KERIError> {
        let mut msg = Vec::new();

        // Get the event, signatures, and couple
        let (serder, sigs, couple): (SerderKERI, Vec<Siger>, Option<Vec<u8>>) =
            self.get_own_event(sn, allow_partially_signed)?;

        // Add the raw event message
        msg.extend_from_slice(serder.raw());

        // Add controller indexed signatures counter and signatures
        let sig_counter = BaseCounter::from_code_and_count(
            Some(ctr_dex_1_0::CONTROLLER_IDX_SIGS),
            Some(sigs.len() as u64),
            None,
        )
        .map_err(|e| {
            KERIError::ValidationError(format!("Failed to create signature counter: {}", e))
        })?;

        msg.extend(sig_counter.qb64b());

        // Add each signature
        for sig in &sigs {
            msg.extend(sig.qb64b());
        }

        // Add couple if present
        if let Some(couple_data) = couple {
            let couple_counter = BaseCounter::from_code_and_count(
                Some(ctr_dex_1_0::SEAL_SOURCE_COUPLES),
                Some(1),
                None,
            )
            .map_err(|e| {
                KERIError::ValidationError(format!("Failed to create couple counter: {}", e))
            })?;

            msg.extend(couple_counter.qb64b());
            msg.extend(couple_data);
        }

        Ok(msg)
    }

    /// Create own inception event message with attachments
    /// This is a convenience method that calls make_own_event with sn=0
    ///
    /// # Parameters
    /// * `allow_partially_signed` - If true, also check partially signed events database
    ///
    /// # Returns
    /// * `Ok(Vec<u8>)` - Complete inception event message with attachments
    /// * `Err(KERIError)` - On missing event or database error
    pub fn make_own_inception(&self, allow_partially_signed: bool) -> Result<Vec<u8>, KERIError> {
        self.make_own_event(0, allow_partially_signed)
    }

    /// Process all cues and return combined messages
    ///
    /// # Parameters
    /// * `cues` - Deque of cue objects to process
    ///
    /// # Returns
    /// * `Ok(Vec<u8>)` - Combined outgoing messages from all cues
    /// * `Err(KERIError)` - On processing error
    pub fn process_cues(
        &mut self,
        cues: &mut VecDeque<IndexMap<String, SadValue>>,
    ) -> Result<Vec<u8>, KERIError> {
        let mut msgs = Vec::new();

        for msg_result in self.process_cues_iter(cues)? {
            let msg = msg_result?;
            msgs.extend(msg);
        }

        Ok(msgs)
    }

    /// Process cues iteratively, yielding messages for each cue
    ///
    /// # Parameters
    /// * `cues` - Deque of cue objects to process
    ///
    /// # Returns
    /// * `Ok(Vec<Result<Vec<u8>, KERIError>>)` - Iterator of message results
    /// * `Err(KERIError)` - On processing error
    pub fn process_cues_iter(
        &mut self,
        cues: &mut VecDeque<IndexMap<String, SadValue>>,
    ) -> Result<Vec<Result<Vec<u8>, KERIError>>, KERIError> {
        let mut results = Vec::new();

        while let Some(cue) = cues.pop_front() {
            let mut msgs = Vec::new();

            // Get the cue kind
            let cue_kin = cue.get("kin").and_then(|v| v.as_str()).ok_or_else(|| {
                KERIError::ValidationError("Missing or invalid cue kind".to_string())
            })?;

            match cue_kin {
                "receipt" => {
                    // Handle receipt cue
                    let cued_serder_data = cue.get("serder").ok_or_else(|| {
                        KERIError::ValidationError("Missing serder in receipt cue".to_string())
                    })?;

                    // Convert SadValue to SerderKERI (assuming there's a conversion method)
                    let cued_serder = self.sad_value_to_serder(cued_serder_data)?;
                    let cued_ked = cued_serder.ked();

                    // Get the identifier from the event
                    let cued_pre = cued_ked.get("i").and_then(|v| v.as_str()).ok_or_else(|| {
                        KERIError::ValidationError("Missing identifier in cued event".to_string())
                    })?;

                    // Create prefixer to check transferability
                    let cued_prefixer = Prefixer::from_qb64(cued_pre).map_err(|e| {
                        KERIError::ValidationError(format!("Failed to create prefixer: {}", e))
                    })?;

                    info!(
                        "{} got cue: kin={} {}",
                        self.pre.as_deref().unwrap_or("None"),
                        cue_kin,
                        cued_serder.said().unwrap_or("None")
                    );
                    debug!("event=\n{}\n", cued_serder.pretty(None));

                    // Check if this is an inception event
                    if let Some(ilk) = cued_ked.get("t").and_then(|v| v.as_str()) {
                        if ilk == "icp" {
                            // Create digest key for our own inception
                            let pre = self.pre.as_ref().ok_or_else(|| {
                                KERIError::ValidationError("Missing habitat prefix".to_string())
                            })?;

                            let iserder = self.iserder()?;
                            let iserder_said = iserder.said().ok_or_else(|| {
                                KERIError::ValidationError("Missing inception SAID".to_string())
                            })?;

                            let dgkey = dg_key(pre, iserder_said);
                            let mut found = false;

                            if cued_prefixer.transferable() {
                                // Check for transferable receipts (VRCs)
                                let vrcs_iter =
                                    self.db.vrcs.get_iter::<_, Vec<u8>>(&[&dgkey]).map_err(
                                        |e| {
                                            KERIError::DatabaseError(format!(
                                                "Failed to get VRCs: {}",
                                                e
                                            ))
                                        },
                                    )?;

                                for quadruple_result in vrcs_iter {
                                    let quadruple = quadruple_result.map_err(|e| {
                                        KERIError::DatabaseError(format!(
                                            "Failed to deserialize VRC: {}",
                                            e
                                        ))
                                    })?;

                                    if let Ok(quadruple_str) = String::from_utf8(quadruple) {
                                        if quadruple_str.starts_with(cued_pre) {
                                            found = true;
                                            break;
                                        }
                                    }
                                }
                            } else {
                                // Check for non-transferable receipts (RCTs)
                                let rcts_iter =
                                    self.db.rcts.get_iter::<_, Vec<u8>>(&[&dgkey]).map_err(
                                        |e| {
                                            KERIError::DatabaseError(format!(
                                                "Failed to get RCTs: {}",
                                                e
                                            ))
                                        },
                                    )?;

                                for couple_result in rcts_iter {
                                    let couple = couple_result.map_err(|e| {
                                        KERIError::DatabaseError(format!(
                                            "Failed to deserialize RCT: {}",
                                            e
                                        ))
                                    })?;

                                    if let Ok(couple_str) = String::from_utf8(couple) {
                                        if couple_str.starts_with(cued_pre) {
                                            found = true;
                                            break;
                                        }
                                    }
                                }
                            }

                            if !found {
                                // No receipt from remote, so send our own inception
                                let inception_msg = self.make_own_inception(false)?;
                                msgs.extend(inception_msg);
                            }
                        }
                    }

                    // Create receipt for the cued event
                    let receipt_msg = self.receipt(&cued_serder)?;
                    msgs.extend(receipt_msg);

                    results.push(Ok(msgs));
                }

                "replay" => {
                    // Handle replay cue
                    let replay_msgs = cue.get("msgs").ok_or_else(|| {
                        KERIError::ValidationError("Missing msgs in replay cue".to_string())
                    })?;

                    // Convert SadValue to Vec<u8> (assuming there's a conversion method)
                    let msgs = self.sad_value_to_bytes(replay_msgs)?;
                    results.push(Ok(msgs));
                }

                "reply" => {
                    // Handle reply cue
                    let data = cue
                        .get("data")
                        .and_then(|v| self.sad_value_to_indexmap(v).ok());

                    let route = cue.get("route").and_then(|v| v.as_str()).ok_or_else(|| {
                        KERIError::ValidationError("Missing route in reply cue".to_string())
                    })?;

                    let reply_msg = self.reply(
                        route.to_string(),
                        data,
                        None, // stamp
                        None, // version
                        None, // kind
                        None, // last
                        None, // pipelined
                    )?;

                    results.push(Ok(reply_msg));
                }

                _ => {
                    // Handle unknown cue kinds - for now just log and continue
                    warn!("Unhandled cue kind: {}", cue_kin);
                    // TODO: Implement handlers for other cue kinds:
                    // - "query" for various types of queries
                    // - "notice" for new event notifications
                    // - "witness" to create witness receipts
                    // - "noticeBadCloneFN" for bad clone notifications
                    // - "approveDelegation" for delegation approval
                    // - "keyStateSaved" for key state persistence
                    // - "psUnescrow" for partial signature unescrow
                    // - "stream" for streaming operations
                    // - "invalid" for invalid events
                    // - "remoteMemberedSig" for remote member signatures

                    results.push(Ok(Vec::new())); // Return empty message for unhandled cues
                }
            }
        }

        Ok(results)
    }

    /// Returns whether this habitat can act as a witness
    ///
    /// # Returns
    /// * `bool` - Always true for base implementation
    pub fn witnesser(&self) -> bool {
        true
    }

    // Helper methods for SadValue conversions

    /// Convert SadValue to SerderKERI
    fn sad_value_to_serder(&self, sad_value: &SadValue) -> Result<SerderKERI, KERIError> {
        match sad_value {
            SadValue::Object(map) => SerderKERI::from_sad(&Sadder::from(map.clone())),
            _ => Err(KERIError::ValidationError(
                "Expected object for serder".to_string(),
            )),
        }
    }

    /// Convert SadValue to Vec<u8>
    fn sad_value_to_bytes(&self, sad_value: &SadValue) -> Result<Vec<u8>, KERIError> {
        match sad_value {
            SadValue::String(s) => Ok(s.as_bytes().to_vec()),
            SadValue::Array(arr) => {
                // Convert array of numbers to bytes
                let mut bytes = Vec::new();
                for val in arr {
                    if let Some(num) = val.as_u64() {
                        if num <= 255 {
                            bytes.push(num as u8);
                        } else {
                            return Err(KERIError::ValidationError(
                                "Byte value out of range".to_string(),
                            ));
                        }
                    } else {
                        return Err(KERIError::ValidationError(
                            "Expected numeric values for bytes".to_string(),
                        ));
                    }
                }
                Ok(bytes)
            }
            _ => Err(KERIError::ValidationError(
                "Cannot convert SadValue to bytes".to_string(),
            )),
        }
    }

    /// Convert SadValue to IndexMap
    fn sad_value_to_indexmap(
        &self,
        sad_value: &SadValue,
    ) -> Result<IndexMap<String, SadValue>, KERIError> {
        match sad_value {
            SadValue::Object(map) => Ok(map.clone()),
            _ => Err(KERIError::ValidationError(
                "Expected object for IndexMap".to_string(),
            )),
        }
    }
}

/// Hab class provides a given identifier controller's local resource environment
/// i.e. hab or habitat. Includes dependency injection of database, keystore,
/// configuration file as well as Kevery and key store Manager.
///
/// # Attributes (Injected)
/// * `ks` - LMDB key store
/// * `db` - LMDB data base for KEL etc
/// * `cf` - Config file instance  
/// * `mgr` - Creates and rotates keys in key store
/// * `rtr` - Routes reply 'rpy' messages
/// * `rvy` - Factory that processes reply 'rpy' messages
/// * `kvy` - Factory for local processing of local event msgs
/// * `psr` - Parses local messages for .kvy .rvy
///
/// # Attributes
/// * `name` - Alias of controller
/// * `pre` - qb64 prefix of own local controller or None if new
/// * `temp` - True means testing: use weak level when salty algo for stretching
///   in key creation for incept and rotate of keys for this hab.pre
/// * `inited` - True means fully initialized wrt databases. False means not yet fully initialized
/// * `delpre` - Delegator prefix if any else None
///
/// # Properties
/// * `kever` - Instance of key state of local controller
/// * `kevers` - Of eventing.Kever instances from KELs in local db keyed by qb64 prefix.
///   Read through cache of kevers of states for KELs in db.states
/// * `iserder` - Own inception event
/// * `prefixes` - Local prefixes for .db
/// * `accepted` - True means accepted into local KEL. False otherwise

pub struct Hab<'db, R> {
    /// Base habitat functionality
    pub base: BaseHab<'db, R>,
    /// Configuration file instance
    pub cf: Option<Arc<Configer>>,
}

// Implement Deref to delegate read-only access to BaseHab
impl<'db, R> Deref for Hab<'db, R> {
    type Target = BaseHab<'db, R>;

    fn deref(&self) -> &Self::Target {
        &self.base
    }
}

// Implement DerefMut to delegate mutable access to BaseHab
impl<'db, R> DerefMut for Hab<'db, R> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.base
    }
}

impl<'db, R> Hab<'db, R> {
    /// Create a new Hab instance
    ///
    /// # Parameters
    /// * `ks` - Keeper instance for key management
    /// * `db` - Baser database instance
    /// * `mgr` - Manager for key operations
    /// * `rtr` - Optional router for reply messages
    /// * `rvy` - Revery for processing reply messages
    /// * `kvy` - Kevery for processing event messages
    /// * `psr` - Parser for message processing
    /// * `cf` - Optional configuration file
    /// * `name` - Alias name for the controller
    /// * `ns` - Optional namespace
    /// * `pre` - Optional existing prefix
    /// * `temp` - Testing mode flag
    /// * `delpre` - Optional delegator prefix
    ///
    /// # Returns
    /// * `Result<Self, KERIError>` - New Hab instance or error
    pub fn new(
        ks: Keeper<'db>,
        db: Baser<'db>,
        mgr: Manager<'db>,
        rtr: Option<Arc<Router>>,
        rvy: Revery<'db>,
        kvy: Kevery<'db>,
        psr: Parser<'db, R>,
        cf: Option<Arc<Configer>>,
        name: String,
        ns: Option<String>,
        pre: Option<String>,
        temp: bool,
        delpre: Option<String>,
    ) -> Result<Self, KERIError> {
        let base = BaseHab::new(ks, db, mgr, rtr, rvy, kvy, psr, name, ns, pre, temp)?;

        let mut hab = Hab { base, cf };

        // Set delegator prefix if provided
        hab.base.delpre = delpre;

        Ok(hab)
    }

    /// Create a new habitat with the given parameters.
    /// This method handles both replay (from secrecies) and normal inception flows.
    pub fn make(
        &mut self,
        secrecies: Option<Vec<Vec<String>>>,
        iridx: Option<usize>,
        code: Option<&str>,
        dcode: Option<&str>,
        icode: Option<&str>,
        transferable: Option<bool>,
        isith: Option<Tholder>,
        icount: Option<usize>,
        nsith: Option<Tholder>,
        ncount: Option<usize>,
        toad: Option<u32>,
        wits: Option<Vec<String>>,
        delpre: Option<String>,
        est_only: Option<bool>,
        d_n_d: Option<bool>,
        hidden: Option<bool>,
        data: Option<Vec<u8>>,
        algo: Option<Algos>,
        salt: Option<Vec<u8>>,
        tier: Option<Tiers>,
    ) -> Result<SerderKERI, KERIError> {
        // Check if resources are opened
        if !(self.ks.opened() && self.db.opened() && self.cf.as_ref().map_or(false, |cf| cf.opened))
        {
            return Err(KERIError::ClosedError(
                "Attempt to make Hab with unopened resources.".to_string(),
            ));
        }

        let transferable = transferable.unwrap_or(true);
        let icount = icount.unwrap_or(1);
        let mut ncount = ncount.unwrap_or(icount);
        let mut nsith = nsith.unwrap_or_else(|| isith.clone().unwrap_or_default());
        let mut code = code.unwrap_or(mtr_dex::BLAKE3_256);
        let hidden = hidden.unwrap_or(false);
        let iridx = iridx.unwrap_or(0);

        // Handle non-transferable case
        if !transferable {
            ncount = 0;
            nsith = Tholder::new(None, None, Some(TholderSith::HexString("0".to_string())))?;
            code = mtr_dex::ED25519N;
        }

        // Create stem from name and namespace
        let stem = if let Some(ref ns) = self.ns {
            format!("{}{}", ns, self.name)
        } else {
            self.name.clone()
        };
        let temp_clone = self.temp.clone();
        let (verfers, digers) = if let Some(secrecies) = secrecies {
            // Replay flow
            let (ipre, _) = self.mgr.ingest(
                secrecies,
                Some(iridx),
                Some(ncount),
                None, // ncode
                None, // dcode
                algo,
                salt,
                Some(stem),
                tier,
                None, // rooted
                Some(transferable),
                Some(temp_clone),
            )?;

            self.mgr.replay(
                ipre.as_bytes(),
                dcode,
                Some(false), // advance = false
                None,        // erase
            )?
        } else {
            // Normal inception flow

            self.mgr.incept(
                None, // icodes
                Some(icount),
                icode,
                None, // ncodes
                Some(ncount),
                None, // ncode
                dcode.map(|s| s.to_string()),
                algo,
                salt,
                Some(&stem),
                tier,
                None, // rooted
                Some(transferable),
                Some(temp_clone),
            )?
        };

        // Call parent make method (BaseHab::make)
        let serder = self.base.make(
            d_n_d,
            Some(code),
            data,
            delpre.clone(),
            est_only,
            isith,
            verfers.clone(),
            Some(nsith),
            Some(digers),
            toad,
            wits,
        )?;

        // Set the new prefix from the serder - extract "i" field from ked
        let ked = serder.ked();
        if let Some(SadValue::String(pre)) = ked.get("i") {
            self.pre = Some(pre.clone());
        } else {
            return Err(KERIError::ValueError(
                "Invalid inception event: missing or invalid 'i' field".to_string(),
            ));
        }

        // Move from old prefix to new prefix
        if let Some(ref pre) = self.pre.clone() {
            let opre = verfers[0].qb64(); // default zeroth original pre from key store
            self.mgr.move_prefix(opre.as_bytes(), pre.as_bytes())?; // move to incept event pre

            // Create habitat record
            let habord = HabitatRecord {
                hid: pre.clone(),
                name: Some(self.name.clone()),
                domain: self.ns.clone(),
                ..Default::default()
            };

            // Must add self.pre to self.prefixes before calling processEvent so that
            // Kever.locallyOwned or Kever.locallyDelegated or Kever.locallyWitnessed
            // evaluates correctly when processing own inception event.
            if !hidden {
                self.save(habord)?;
                self.db.prefixes.insert(pre.clone());
            }

            // Sign handles group hab with .mhab case
            let sigers = self.sign(
                serder.raw(),
                Some(verfers),
                None, // indexed (defaults to true)
                None, // indices
                None, // ondices
                None, // ponly
            )?;

            // During delegation initialization of a habitat we ignore the MissingDelegationError and
            // MissingSignatureError
            match self.kvy.process_event(
                serder.clone(),
                sigers,
                None, // wigers
                None, // delseqner
                None, // delsaider
                None, // firner
                None, // dater
                None, // eager
                None, // local (uses kvy.local default)
            ) {
                Ok(_) => {}
                Err(KERIError::MissingSignatureError(_)) => {
                    // This is acceptable during delegation initialization - just pass
                }
                Err(ex) => {
                    return Err(KERIError::ConfigurationError(format!(
                        "Improper Habitat inception for pre={}: {}",
                        pre, ex
                    )));
                }
            }

            // Read in self.cf config file and process any oobis or endpoints
            self.reconfigure(); // should we do this for new Habs not loaded from db

            self.inited = true;
            Ok(serder)
        } else {
            Err(KERIError::ValueError(
                "Failed to set prefix after inception".to_string(),
            ))
        }
    }

    /// Save habitat record to database and register name
    ///
    /// # Parameters
    /// * `habord` - HabitatRecord to save
    ///
    /// # Returns
    /// * `Result<(), KERIError>` - Ok if successful, error otherwise
    ///
    /// # Errors
    /// * Returns error if AID already exists with the given name
    pub fn save(&mut self, habord: HabitatRecord) -> Result<(), KERIError> {
        // Get the current prefix - should be set by this point
        let pre = self.pre.as_ref().ok_or_else(|| {
            KERIError::ValueError("Cannot save habitat: prefix not set".to_string())
        })?;

        // Save the habitat record keyed by prefix
        self.db.habs.pin(&[pre.as_bytes()], &habord).map_err(|e| {
            KERIError::DatabaseError(format!("Failed to save habitat record: {}", e))
        })?;

        // Prepare namespace - empty string if None
        let ns = self.ns.as_deref().unwrap_or("");

        // Check if name already exists in this namespace
        let existing: Option<Vec<u8>> = self
            .db
            .names
            .get(&[ns.as_bytes(), self.name.as_bytes()])
            .map_err(|e| {
            KERIError::DatabaseError(format!("Failed to check existing name: {}", e))
        })?;

        let existing_string = existing.map(|bytes| String::from_utf8_lossy(&bytes).to_string());

        if existing_string.is_some() {
            return Err(KERIError::ValueError(
                "AID already exists with that name".to_string(),
            ));
        }

        // Save the name mapping (namespace, name) -> prefix
        self.db
            .names
            .pin(&[ns.as_bytes(), self.name.as_bytes()], &pre.as_bytes())
            .map_err(|e| KERIError::DatabaseError(format!("Failed to save name mapping: {}", e)))?;

        Ok(())
    }
    /// Get the algorithm used for this habitat
    ///
    /// # Returns
    /// * `Result<String, KERIError>` - The algorithm name or error
    pub fn algo(&self) -> Result<String, KERIError> {
        let pre = self
            .pre
            .as_ref()
            .ok_or_else(|| KERIError::ValueError("Cannot get algo: prefix not set".to_string()))?;

        let pp = self.ks.prms.get(&[pre.as_bytes()])?.ok_or_else(|| {
            KERIError::ValueError(format!("No parameters found for prefix: {}", pre))
        })?;

        Ok(pp.algo)
    }

    /// Perform rotation operation. Register rotation in database.
    /// Returns rotation message with attached signatures.
    ///
    /// # Parameters
    /// * `isith` - Current signing threshold
    /// * `nsith` - Next signing threshold
    /// * `ncount` - Next number of signing keys
    /// * `toad` - Witness threshold after cuts and adds
    /// * `cuts` - List of witness prefixes to be removed from witness list
    /// * `adds` - List of witness prefixes to be added to witness list
    /// * `data` - List of committed data such as seals
    ///
    /// # Returns
    /// * `Result<Vec<u8>, KERIError>` - Rotation message with signatures or error
    pub fn rotate(
        &mut self,
        isith: Option<Tholder>,
        nsith: Option<Tholder>,
        ncount: Option<u32>,
        toad: Option<u32>,
        cuts: Option<Vec<String>>,
        adds: Option<Vec<String>>,
        data: Option<Vec<u8>>,
    ) -> Result<Vec<u8>, KERIError> {
        let pre = self
            .pre
            .clone()
            .ok_or_else(|| KERIError::ValueError("Cannot rotate: prefix not set".to_string()))?;

        // Set defaults for counts - use len of prior next digers as default
        let ncount = ncount.unwrap_or({
            let kever = self.kever()?;
            match kever.ndigers.as_ref() {
                Some(digers) => digers.len() as u32,
                None => 0,
            }
        });

        // Try to replay first, fallback to rotate if IndexError
        let (verfers, digers) = match self.mgr.replay(
            pre.as_bytes(),
            None,       // dcode
            Some(true), // advance
            Some(true), // erase
        ) {
            Ok((verfers, digers)) => (verfers, digers),
            Err(KERIError::IndexError(_)) => {
                // Old next is new current - need to rotate
                self.mgr.rotate(
                    pre.as_bytes(),
                    None,                  // ncodes
                    Some(ncount as usize), // ncount
                    None,                  // ncode - will use default ED25519
                    None,                  // dcode - will use default BLAKE3_256
                    Some(true),            // transferable
                    Some(self.temp),       // temp
                    Some(true),            // erase
                )?
            }
            Err(e) => return Err(e),
        };

        // Call the parent rotate method from BaseHab
        self.base.rotate(
            None, // count - not used in BaseHab::rotate
            Some(ncount),
            isith,
            nsith,
            toad,
            cuts,
            adds,
            data,
        )
    }
}
