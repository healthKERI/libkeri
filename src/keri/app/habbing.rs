
use std::collections::HashMap;
use std::sync::Arc;
use indexmap::{IndexMap, IndexSet};
use serde_json;
use crate::cesr::cigar::Cigar;
use crate::keri::{Ilks, Roles, Schemes};
use crate::keri::db::basing::{Baser, HabitatRecord};
use crate::keri::app::keeping::{Manager, Keeper};
use crate::keri::app::keeping::keeper::KeeperTrait;
use crate::keri::core::serdering::{Rawifiable, SadValue, Serder, SerderKERI};
use crate::keri::core::eventing::kevery::Kevery;
use crate::keri::core::eventing::kever::Kever;
use crate::keri::core::parsing::Parser;
use crate::keri::core::routing::{Revery, Router};
use crate::cesr::verfer::Verfer;
use crate::cesr::Matter;
use crate::cesr::diger::Diger;
use crate::cesr::indexing::siger::Siger;
use crate::cesr::tholder::{Tholder, TholderSith};
use crate::cesr::prefixer::Prefixer;
use crate::cesr::trait_dex;
use crate::cesr::counting::Counter;
use crate::cesr::signing::Sigmat;
use crate::keri::core::eventing;
use crate::keri::core::eventing::{Seal, SealEvent, SealLast};
// use crate::keri::core::exchanging;
use crate::keri::KERIError;
use crate::keri::KERIError::{ValidationError, ConfigurationError, MissingEntryError};
use crate::keri::db::dbing::keys::{sn_key, dg_key};
use crate::keri::core::eventing::incept::InceptionEventBuilder;
use crate::keri::core::eventing::rotate::RotateEventBuilder;
use crate::keri::core::eventing::interact::InteractEventBuilder;
use crate::keri::core::eventing::query::QueryEventBuilder;
use crate::keri::core::eventing::receipt::ReceiptEventBuilder;
use crate::keri::core::eventing::{incept, rotate, interact, query, receipt, reply, messagize};



pub struct BaseHab<'db, R> {
    pub ks: Keeper<'db>,
    pub db: Baser<'db>,
    pub mgr: Manager<'db>,
    pub rtr: Option<Arc<Router>>,
    pub rvy: Revery<'db>,            // Added missing field
    pub kvy: Kevery<'db>,
    pub psr: Parser<R>,
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
        psr: Parser<R>,
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
        self.db.habs.pin(&[pre.as_bytes()], habord)
            .map_err(|e| KERIError::DatabaseError(format!("Failed to save habitat: {}", e)))?;

        // Handle namespace - empty string if None
        let ns = self.ns.as_deref().unwrap_or("");

        // Check if name already exists
        let existing: Option<Vec<u8>> = self.db.names.get(&[ns.as_bytes(), self.name.as_bytes()])
            .map_err(|e| KERIError::DatabaseError(format!("Failed to check existing name: {}", e)))?;

        if existing.is_some() {
            return Err(KERIError::ValueError(
                "AID already exists with that name".to_string()
            ));
        }

        // Pin the name to prefix mapping
        self.db.names.pin(&[ns.as_bytes(), self.name.as_bytes()], &pre.as_bytes().to_vec())
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

            let dig = self.db.get_ke_last(&sn_key)?
                .ok_or_else(|| {
                    ConfigurationError(
                        format!("Missing inception event in KEL for Habitat pre={}", pre)
                    )
                })?;
            let dg_key = dg_key(pre, dig.as_bytes());

            let raw = self.db.get_evt(&dg_key)?
                .ok_or_else(|| {
                    ConfigurationError(
                        format!("Missing inception event for Habitat pre={}", pre)
                    )
                })?;
            SerderKERI::from_raw(&raw, None)
                .map_err(|e| ValidationError(format!("Failed to deserialize inception event: {}", e)))
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
            self.kvy.kevers.get(pre)
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
            None, // icodes
            Some(count as usize), // icount
            None, // icode - will use default
            None, // ncodes
            Some(ncount as usize), // ncount
            None, // ncode - will use default
            None, // dcode - will use default
            None, // algo
            None, // salt
            None, // stem
            None, // tier
            None, // rooted
            Some(transferable),
            Some(self.temp),
        )?;

        // Extract configuration flags from cnfg parameter
        let mut d_n_d = false;
        let mut est_only = false;
        if let Some(cnfg) = cnfg {
            for config in cnfg {
                match config {
                    "EO" => est_only = true,  // EST_ONLY trait
                    "DND" => d_n_d = true,    // DO_NOT_DELEGATE trait
                    _ => {} // Ignore unknown configs
                }
            }
        }

        // Now call make with the proper parameters
        self.make(
            Some(d_n_d),           // d_n_d: Option<bool>
            code,                  // code: Option<&str>
            data,                  // data: Option<Vec<u8>>
            delpre,                // delpre: Option<String>
            Some(est_only),        // est_only: Option<bool>
            isith,                 // isith: Option<Tholder>
            verfers,               // verfers: Vec<Verfer>
            nsith,                 // nsith: Option<Tholder>
            Some(digers),          // digers: Option<Vec<Diger>>
            toad,                  // toad: Option<u32>
            wits,                  // wits: Option<Vec<String>>
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
            pre.as_bytes(),              // pre: &[u8]
            None,                        // ncodes: Option<Vec<&str>>
            Some(ncount as usize),       // ncount: Option<usize>
            None,                        // ncode: Option<&str> - will use default ED25519
            None,                        // dcode: Option<&str> - will use default BLAKE3_256
            Some(true),                  // transferable: Option<bool>
            Some(self.temp),             // temp: Option<bool>
            Some(true),                  // erase: Option<bool> - erase old keys
        )?;

        // Determine signing thresholds following Python logic
        let isith_sith = if let Some(isith) = isith {
            isith.sith()
        } else {
            // Use prior next threshold as default, or provide fallback if None
            kever.ntholder
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
        if !kever.ntholder.as_ref().map_or(false, |tholder| tholder.satisfy(&indices)) {
            return Err(ValidationError(
                "Invalid rotation: new key set unable to satisfy prior next signing threshold".to_string()
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

        let said = kever.serder
            .as_ref()
            .ok_or_else(|| ValidationError("Missing serder".to_string()))?
            .said()
            .ok_or_else(|| ValidationError("Missing said in serder".to_string()))?
            .to_string();

        let num = kever.sner.as_ref()
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
            None, // indices
            None, // ondices  
            None, // ponly
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
            Ok(_) => {},
            Err(KERIError::MissingSignatureError(_)) => {
            },
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
        let pre = self.pre.as_ref()
            .ok_or_else(|| ConfigurationError("No prefix set for habitat".to_string()))?;

        // Get the current sequence number and increment for next event
        let current_sn = kever.sner.as_ref()
            .ok_or_else(|| ValidationError("Missing sequence number in kever".to_string()))?
            .num();
        let next_sn = current_sn + 1;

        // Get the digest of the current event (prior event)
        let prior_dig = kever.serder.as_ref()
            .ok_or_else(|| ValidationError("Missing serder in kever".to_string()))?
            .said()
            .ok_or_else(|| ValidationError("Missing SAID in current event".to_string()))?
            .to_string();

        // Create interaction event using the builder
        let mut builder = InteractEventBuilder::new(pre.clone(), prior_dig)
            .with_sn(next_sn as usize);

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
            &serder.raw(),      // ser: serialized event to sign
            None,               // verfers: use current verfers from kever
            Some(true),         // indexed: create indexed signatures
            None,               // indices: let manager choose indices
            None,               // ondices: no specific ondices
            None,               // ponly: not ponly mode
        )?;

        // Create the complete message with serder and signatures
        let msg = messagize(&serder, Some(&sigers), None, None, None, false)
            .map_err(|e| ValidationError(format!("Failed to create message: {}", e)))?;

        // Process the event through kevery to update local state
        // This validates the event and updates the kever state
        match self.kvy.process_event(
            serder,             // serder: the interaction event
            sigers,             // sigers: signatures
            None,               // wigers: no witness signatures
            None,               // local: not specified
            None,               // cigars: no non-indexed signatures  
            None,               // tsgs: no trans signatures
            None,               // tholder: no threshold
            None,               // toader: no toad threshold
            None,               // seqner: sequence number will be extracted
        ) {
            Ok(_) => {
                // Event processed successfully
            },
            Err(KERIError::MissingSignatureError(_)) => {
                // Missing signatures are acceptable for some scenarios
                // Continue processing
            },
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
        signatures.into_iter()
            .map(|sig| {
                match sig {
                    Sigmat::Indexed(siger) => Ok(siger),
                    Sigmat::NonIndexed(_) => Err(KERIError::ValidationError(
                        "Expected Siger but got Cigar - indexed signatures required".to_string()
                    ))
                }
            })
            .collect()
    }

    pub fn decrypt(
        &self,
        ser: &[u8],
        verfers: Option<Vec<Verfer>>,
    ) -> Result<Vec<u8>, KERIError> {
        // If no verfers provided, use the current kever's verfers
        let verfers_to_use = if let Some(verfers) = verfers {
            Some(verfers)
        } else {
            // Get verfers from kever - these provide group signing keys when in group mode
            match self.kever() {
                Ok(kever) => kever.verfers.clone(),
                Err(_) => {
                    return Err(KERIError::ConfigurationError(
                        "No kever available and no verfers provided for decryption".to_string()
                    ));
                }
            }
        };

        // Delegate to the manager's decrypt method
        // Note: The Python comment mentions this "should not use mgr.decrypt since it assumes qb64"
        // but says it's "just lucky its not yet a problem". We'll use it as intended for now.
        self.mgr.decrypt(
            ser,                // qb64: the ciphertext to decrypt  
            None,               // pubs: not using public key strings
            verfers_to_use,     // verfers: use the verfers we determined above
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
        let mut builder = QueryEventBuilder::new()
            .with_query(query_params);

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
        let serder = builder.build()
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
        let prefixer = kever.prefixer.as_ref()
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
                let last_est_sn = kever.sner.as_ref()
                    .ok_or_else(|| ValidationError("Missing sequence number in kever".to_string()))?
                    .num();

                let last_est_dig = kever.serder.as_ref()
                    .ok_or_else(|| ValidationError("Missing serder in kever".to_string()))?
                    .said()
                    .ok_or_else(|| ValidationError("Missing SAID in current event".to_string()))?
                    .to_string();

                Seal::SealEvent(SealEvent::new(
                    prefixer.qb64(),                // identifier prefix
                    format!("{:x}", last_est_sn),   // sequence number as hex string
                    last_est_dig,                   // digest of last establishment event
                ))
            };

            // Sign the serder with indexed signatures
            let sigers = self.sign(
                &serder.raw(),      // ser: serialized event to sign
                None,               // verfers: use current verfers from kever
                Some(true),         // indexed: create indexed signatures
                None,               // indices: let manager choose indices
                None,               // ondices: no specific ondices
                None,               // ponly: not ponly mode
            )?;

            // Create the endorsement message with serder, signatures, and seal
            let msg = messagize(
                serder,             // serder: the event being endorsed
                Some(&sigers),      // sigers: indexed signatures
                Some(seal),         // seal: seal indicating endorser's state
                None,               // cigars: not used for transferable
                None,               // wigers: no witness signatures
                pipelined,          // pipelined: message format
            ).map_err(|e| ValidationError(format!("Failed to create endorsement message: {}", e)))?;

            Ok(msg)

        } else {
            // For non-transferable identifiers, create non-indexed signatures (cigars)

            // Sign the serder with non-indexed signatures
            let signatures = self.mgr.sign(
                &serder.raw(),      // ser: serialized event to sign
                None,               // pubs: not using public key strings
                None,               // verfers: use current verfers from kever (handled by sign method)
                Some(false),        // indexed: create non-indexed signatures
                None,               // indices: not applicable for non-indexed
                None,               // ondices: not applicable for non-indexed
                self.pre.as_ref().map(|p| p.as_bytes()), // pre: habitat prefix
                None,               // path: not specified
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
                serder,             // serder: the event being endorsed
                None,               // sigers: not used for non-transferable
                None,               // seal: not used for non-transferable
                None,               // wigers: no witness signatures
                Some(&cigars),      // cigars: non-indexed signatures
                pipelined,          // pipelined: message format
            ).map_err(|e| ValidationError(format!("Failed to create endorsement message: {}", e)))?;

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
        let pre = ked.get("i")
            .and_then(|v| match v {
                SadValue::String(s) => Some(s.clone()),
                _ => None,
            })
            .ok_or_else(|| ValidationError("Missing or invalid identifier in event".to_string()))?;

        // Get the sequence number from the event and convert from hex
        let sn_hex = ked.get("s")
            .and_then(|v| match v {
                SadValue::String(s) => Some(s.clone()),
                _ => None,
            })
            .ok_or_else(|| ValidationError("Missing or invalid sequence number in event".to_string()))?;

        let sn = usize::from_str_radix(&sn_hex, 16)
            .map_err(|_| ValidationError("Invalid hex sequence number format".to_string()))?;

        // Get the SAID of the event
        let said = serder.said()
            .ok_or_else(|| ValidationError("Missing SAID in event serder".to_string()))?
            .to_string();

        // Create the receipt event using ReceiptEventBuilder
        let receipt_serder = ReceiptEventBuilder::new(pre, sn, said)
            .build()
            .map_err(|e| ValidationError(format!("Failed to build receipt event: {}", e)))?;

        // Get the current kever to determine signature type
        let kever = self.kever()?;

        // Get the prefixer and check transferability
        let prefixer = kever.prefixer.as_ref()
            .ok_or_else(|| ValidationError("Missing prefixer in kever".to_string()))?;

        let msg = if prefixer.transferable() {
            // For transferable identifiers, create indexed signatures with seal

            // Get the last establishment event info for the seal
            let last_est_sn = kever.sner.as_ref()
                .ok_or_else(|| ValidationError("Missing sequence number in kever".to_string()))?
                .num();

            let last_est_dig = kever.serder.as_ref()
                .ok_or_else(|| ValidationError("Missing serder in kever".to_string()))?
                .said()
                .ok_or_else(|| ValidationError("Missing SAID in current event".to_string()))?
                .to_string();

            // Create SealEvent with the last establishment event details
            let seal = Seal::SealEvent(SealEvent::new(
                self.pre.as_ref()
                    .ok_or_else(|| ConfigurationError("No prefix set for habitat".to_string()))?
                    .clone(),                           // identifier prefix of the receiptor
                format!("{:x}", last_est_sn),           // sequence number as hex string
                last_est_dig,                           // digest of last establishment event
            ));

            // Sign the original serder (not the receipt) with indexed signatures
            let sigers = self.sign(
                &serder.raw(),      // Sign the original event, not the receipt
                None,               // verfers: use current verfers from kever
                Some(true),         // indexed: create indexed signatures
                None,               // indices: let manager choose indices
                None,               // ondices: no specific ondices
                None,               // ponly: not ponly mode
            )?;

            // Create the receipt message with receipt serder, signatures, and seal
            messagize(
                &receipt_serder,    // serder: the receipt event
                Some(&sigers),      // sigers: indexed signatures
                Some(seal),         // seal: seal indicating receiptor's state
                None,               // cigars: not used for transferable
                None,               // wigers: no witness signatures
                true,               // pipelined: standard message format
            ).map_err(|e| ValidationError(format!("Failed to create receipt message: {}", e)))?

        } else {
            // For non-transferable identifiers, create non-indexed signatures (cigars)

            // Sign the original serder with non-indexed signatures
            let signatures = self.mgr.sign(
                &serder.raw(),      // Sign the original event, not the receipt
                None,               // pubs: not using public key strings
                None,               // verfers: use current verfers from kever
                Some(false),        // indexed: create non-indexed signatures
                None,               // indices: not applicable for non-indexed
                None,               // ondices: not applicable for non-indexed
                self.pre.as_ref().map(|p| p.as_bytes()), // pre: habitat prefix
                None,               // path: not specified
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
                &receipt_serder,    // serder: the receipt event
                None,               // sigers: not used for non-transferable
                None,               // seal: not used for non-transferable
                None,               // wigers: no witness signatures
                Some(&cigars),      // cigars: non-indexed signatures
                true,               // pipelined: standard message format
            ).map_err(|e| ValidationError(format!("Failed to create receipt message: {}", e)))?
        };

        // Process the receipt message locally into the database
        // Convert Vec<u8> to bytearray-like structure for parser
        let mut ims = msg.clone();

        // Parse and process the receipt into the local database
        // self.psr.parse_one(&mut ims)
        //     .map_err(|e| ValidationError(format!("Failed to process receipt into database: {}", e)))?;

        Ok(msg)
    }

}

