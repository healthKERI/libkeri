use crate::cesr::diger::Diger;
use crate::cesr::prefixer::Prefixer;
use crate::cesr::signing::{Decrypter, Encrypter, Salter, Sigmat, Signer};
use crate::cesr::tholder::{Tholder, TholderSith};
use crate::cesr::verfer::Verfer;
use crate::cesr::{mtr_dex, Parsable, Tiers};
use crate::keri::app::keeping::creators::{Algos, Creatory};
use crate::keri::app::keeping::keeper::{PrePrm, PreSit, PubLot, PubSet};
use crate::keri::app::keeping::Keeper;
use crate::keri::app::ri_key;
use crate::keri::help::helping::nowiso8601;
use crate::keri::KERIError;
use crate::Matter;
use chrono::Utc;
use sodiumoxide::crypto::sign::SecretKey;
use std::collections::VecDeque;

/// Manager struct for key pair creation, storage, retrieval, and message signing
///
/// # Attributes
/// * `ks` - Keeper instance for storing public and private keys
/// * `encrypter` - Instance for encrypting secrets, derived from aeid
/// * `decrypter` - Instance for decrypting secrets, derived from seed
/// * `inited` - Flag indicating if manager is fully initialized
/// * `_seed` - Private signing key for the aeid (memory only, never persisted)
/// * `_inits` - Initialization parameters for later setup
pub struct Manager<'db> {
    /// Key store LMDB database instance for storing public and private keys
    pub ks: Keeper<'db>,

    /// Instance for encrypting secrets. Public encryption key derived from aeid
    pub encrypter: Option<Encrypter>,

    /// Instance for decrypting secrets. Private decryption key derived from seed
    pub decrypter: Option<Decrypter>,

    /// True means fully initialized wrt database. False means not yet fully initialized
    pub inited: bool,

    /// qb64b private-signing key (seed) for the aeid
    /// MUST NOT be persisted to database, memory only
    /// Acts as authentication, authorization, and decryption secret
    _seed: Vec<u8>,
}

impl<'db> Manager<'db> {
    /// Create new Manager instance
    ///
    /// # Parameters
    /// * `ks` - Optional Keeper instance
    /// * `seed` - Optional qb64 private signing key for the aeid
    /// * `kwa` - Additional parameters to pass to setup method
    ///
    /// # Returns
    /// * `Result<Self, DBError>` - Result containing new Manager or error
    pub fn new(
        ks: Keeper<'db>,
        seed: Option<Vec<u8>>,
        aeid: Option<Vec<u8>>,
        pidx: Option<usize>,
        algo: Option<Algos>,
        salt: Option<Vec<u8>>,
        tier: Option<Tiers>,
    ) -> Result<Self, KERIError> {
        let mut manager = Manager {
            ks,
            encrypter: None,
            decrypter: None,
            _seed: seed.unwrap_or_default(),
            inited: false,
        };

        if manager.ks.opened() {
            manager.setup(aeid, pidx, algo, salt, tier)?;
        }

        Ok(manager)
    }

    /// Set up manager root or global attributes and properties
    ///
    /// # Parameters
    /// * `aeid` - qb64b non-transferable identifier prefix for authentication and encryption
    /// * `pidx` - Index of next new created key pair sequence
    /// * `algo` - Root algorithm for creating key pairs
    /// * `salt` - qb64 of root salt
    /// * `tier` - Default security tier for root salt
    ///
    /// # Returns
    /// * `Result<(), DBError>` - Success or error
    pub fn setup(
        &mut self,
        aeid: Option<Vec<u8>>,
        pidx: Option<usize>,
        algo: Option<Algos>,
        salt: Option<Vec<u8>>,
        tier: Option<Tiers>,
    ) -> Result<(), KERIError> {
        if !self.ks.opened() {
            return Err(KERIError::ManagerError(
                "Attempt to setup Manager closed keystore database .ks.".to_string(),
            ));
        }

        let aeid = aeid.unwrap_or_default();
        let pidx = pidx.unwrap_or(0);
        let algo = algo.unwrap_or_else(|| Algos::Salty);

        let salt = match salt {
            Some(mut s) => {
                // Validate salt
                if Salter::from_qb64b(&mut s, None)?.qb64b() != s {
                    return Err(KERIError::ManagerError(format!(
                        "Invalid qb64 for salt={:?}",
                        s
                    )));
                }
                s
            }
            None => Salter::new(None, None, None)?.qb64b(),
        };

        let tier = tier.unwrap_or_else(|| Tiers::LOW);

        // Update database if never before initialized
        if self.pidx().is_none() {
            self.set_pidx(pidx)?;
        }

        if self.algo().is_none() {
            self.set_algo(algo)?;
        }

        if self.salt().is_none() {
            self.set_salt(salt)?;
        }

        if self.tier().is_none() {
            self.set_tier(tier)?;
        }

        // Handle aeid initialization/update
        if self.aeid().is_empty() {
            self.update_aeid(aeid, self._seed.clone())?;
        } else {
            self.encrypter = Some(Encrypter::new(None, None, Some(&mut self.aeid()))?);

            if self._seed.is_empty()
                || !self.encrypter.as_ref().unwrap().verify_seed(&self._seed)?
            {
                return Err(KERIError::AuthError(format!(
                    "Last seed missing or provided last seed not associated with last aeid={:?}.",
                    self.aeid()
                )));
            }

            self.decrypter = Some(Decrypter::new(Some(&self._seed), None, None)?);
        }

        self.inited = true;
        Ok(())
    }

    /// Ingest secrecies as a list of lists of secrets organized in event order
    /// to register the sets of secrets of associated externally generated keypair
    /// lists into the database.
    ///
    /// Returns:
    ///     (ipre, verferies) where:
    ///         ipre is prefix index of ingested key pairs needed to fetch later for replay
    ///         verferies is list of lists of all the verfers for the public keys
    ///         from the private keys in secrecies in order of appearance.
    ///
    /// # Parameters
    /// * `secrecies` - List of lists of fully qualified secrets (private keys)
    /// * `iridx` - Initial ridx at which to set PubSit after ingestion
    /// * `ncount` - Count of next public keys for next after end of secrecies
    /// * `ncode` - Derivation code qb64 of all ncount next public keys after end of secrecies
    /// * `dcode` - Derivation code qb64 of next digers after end of secrecies
    /// * `algo` - Key creation algorithm code for next after end of secrecies
    /// * `salt` - qb64 salt for randomization when salty algorithm used
    /// * `stem` - Path modifier used with salt to derive private keys when using salty algorithms
    /// * `tier` - Security criticality tier code when using salty algorithm
    /// * `rooted` - True means derive incept salt from root salt when incept salt not provided
    /// * `transferable` - True means each public key uses transferable derivation code
    /// * `temp` - True is temporary for testing
    pub fn ingest(
        &mut self,
        secrecies: Vec<Vec<String>>,
        iridx: Option<usize>,
        ncount: Option<usize>,
        ncode: Option<&str>,
        dcode: Option<&str>,
        algo: Option<Algos>,
        salt: Option<Vec<u8>>,
        stem: Option<String>,
        tier: Option<Tiers>,
        rooted: Option<bool>,
        transferable: Option<bool>,
        temp: Option<bool>,
    ) -> Result<(String, Vec<Vec<Verfer>>), KERIError> {
        let iridx = iridx.unwrap_or(0);
        let ncount = ncount.unwrap_or(1);
        let ncode = ncode.unwrap_or(mtr_dex::ED25519_SEED);
        let _dcode = dcode.unwrap_or(mtr_dex::BLAKE3_256);
        let algo = algo.unwrap_or(Algos::Salty);
        let rooted = rooted.unwrap_or(true);
        let transferable = transferable.unwrap_or(true);
        let temp = temp.unwrap_or(false);

        if iridx > secrecies.len() {
            return Err(KERIError::ValueError(format!(
                "Initial ridx={} beyond last secrecy.",
                iridx
            )));
        }

        // Configure parameters for creating new keys after ingested sequence
        let salt = if rooted && salt.is_none() {
            self.salt().unwrap_or_else(|| {
                // Fallback to generating a new salt if none exists
                Salter::new(None, None, None).unwrap().qb64b()
            })
        } else {
            salt.unwrap_or_else(|| {
                self.salt().unwrap_or_else(|| {
                    // Fallback to generating a new salt if none exists
                    Salter::new(None, None, None).unwrap().qb64b()
                })
            })
        };

        let tier = if rooted && tier.is_none() {
            self.tier().unwrap_or(Tiers::LOW) // Use LOW as default fallback
        } else {
            tier.unwrap_or_else(|| {
                self.tier().unwrap_or(Tiers::LOW) // Use LOW as default fallback
            })
        };

        let pidx = self.pidx().unwrap_or(0);

        // Create creator for generating new keys after ingested sequence
        let creator = Creatory::new(algo);
        let creator_instance = creator.make(
            Some(&String::from_utf8_lossy(&salt)),
            stem.as_deref(),
            Some(tier.clone()),
        )?;

        let mut ipre = String::new();
        let mut pubs = Vec::new();
        let mut ridx = 0;
        let mut kidx = 0;

        let mut verferies: Vec<Vec<Verfer>> = Vec::new(); // list of lists of verfers
        let mut first = true;
        let mut secrecies = VecDeque::from(secrecies);

        while let Some(csecrets) = secrecies.pop_front() {
            // Create signers from current secrets
            let mut csigners = Vec::new();
            for secret in &csecrets {
                let signer = Signer::new(
                    Some(&base64::decode(secret).map_err(|e| {
                        KERIError::ValueError(format!("Invalid base64 secret: {}", e))
                    })?),
                    None, // Use default code
                    Some(transferable),
                )?;
                csigners.push(signer);
            }

            let csize = csigners.len();
            verferies.push(csigners.iter().map(|s| s.verfer.clone()).collect());

            if first {
                // Secret to encrypt here
                let pp = PrePrm {
                    pidx,
                    algo: format!("{:?}", algo).to_lowercase(),
                    salt: if let Some(ref encrypter) = self.encrypter {
                        encrypter.encrypt(Some(&salt), None, None)?.qb64()
                    } else {
                        String::from_utf8_lossy(&salt).to_string()
                    },
                    stem: stem.clone().unwrap_or_default(),
                    tier: format!("{:?}", tier).to_lowercase(),
                };

                let pre = csigners[0].verfer.qb64b();
                ipre = csigners[0].verfer.qb64();

                let mut pre_copy = pre.clone();
                let prefixer = Prefixer::from_qb64b(&mut pre_copy, None)?;

                if !self.ks.pres.put(&[&pre], &prefixer)? {
                    return Err(KERIError::ValueError(format!(
                        "Already incepted pre={}.",
                        String::from_utf8_lossy(&pre)
                    )));
                }

                if !self.ks.prms.put(&[&pre], &pp)? {
                    return Err(KERIError::ValueError(format!(
                        "Already incepted prm for pre={}.",
                        String::from_utf8_lossy(&pre)
                    )));
                }

                self.set_pidx(pidx + 1)?; // increment so unique
                first = false;
            }

            // Store secrets (private key val keyed by public key)
            let pre = csigners[0].verfer.qb64b();
            for signer in &csigners {
                self.ks
                    .pris
                    .put(&[&signer.verfer.qb64b()], signer, self.encrypter.clone())?;
            }

            pubs = csigners.iter().map(|s| s.verfer.qb64()).collect();
            let pub_set = PubSet { pubs: pubs.clone() };
            self.ks.pubs.put(&[&ri_key(&pre, ridx)], &pub_set)?;

            let dt = nowiso8601();
            if ridx == iridx.saturating_sub(1).max(0) {
                // setup ps.old at this ridx
                let old = if iridx == 0 {
                    Some(PubLot::default()) // defaults ok
                } else {
                    let osith = format!("{:x}", (csize / 2).max(1));
                    let _ost =
                        Tholder::new(None, None, Some(TholderSith::HexString(osith)))?.sith();
                    Some(PubLot {
                        pubs: pubs.clone(),
                        ridx,
                        kidx,
                        dt: dt.clone(),
                    })
                };

                let ps = PreSit {
                    old,
                    new: PubLot::default(), // .new and .nxt are default
                    nxt: PubLot::default(),
                };

                if !self.ks.sits.pin(&[&pre], &ps)? {
                    return Err(KERIError::ValueError(format!(
                        "Problem updating pubsit db for pre={}.",
                        String::from_utf8_lossy(&pre)
                    )));
                }
            }

            if ridx == iridx {
                // setup ps.new at this ridx
                let mut ps = self.ks.sits.get(&[&pre])?.ok_or_else(|| {
                    KERIError::ValueError(format!(
                        "Attempt to rotate nonexistent pre={}.",
                        String::from_utf8_lossy(&pre)
                    ))
                })?;

                let new = PubLot {
                    pubs: pubs.clone(),
                    ridx,
                    kidx,
                    dt: dt.clone(),
                };
                ps.new = new;

                if !self.ks.sits.pin(&[&pre], &ps)? {
                    return Err(KERIError::ValueError(format!(
                        "Problem updating pubsit db for pre={}.",
                        String::from_utf8_lossy(&pre)
                    )));
                }
            }

            if ridx == iridx + 1 {
                // set up ps.nxt at this ridx
                let mut ps = self.ks.sits.get(&[&pre])?.ok_or_else(|| {
                    KERIError::ValueError(format!(
                        "Attempt to rotate nonexistent pre={}.",
                        String::from_utf8_lossy(&pre)
                    ))
                })?;

                let nxt = PubLot {
                    pubs: pubs.clone(),
                    ridx,
                    kidx,
                    dt: dt.clone(),
                };
                ps.nxt = nxt;

                if !self.ks.sits.pin(&[&pre], &ps)? {
                    return Err(KERIError::ValueError(format!(
                        "Problem updating pubsit db for pre={}.",
                        String::from_utf8_lossy(&pre)
                    )));
                }
            }

            ridx += 1; // next ridx
            kidx += csize; // next kidx
        }

        // create nxt signers after ingested signers
        let nsigners = creator_instance.create(
            None,
            Some(ncount),
            Some(ncode),
            Some(pidx),
            Some(ridx),
            Some(kidx),
            Some(transferable),
            Some(temp),
        );

        // Get pre from the first ingested signer
        let pre = if !verferies.is_empty() && !verferies[0].is_empty() {
            verferies[0][0].qb64b()
        } else {
            return Err(KERIError::ValueError(
                "No signers were ingested".to_string(),
            ));
        };

        // store secrets (private key val keyed by public key)
        for signer in &nsigners {
            self.ks
                .pris
                .put(&[&signer.verfer.qb64b()], signer, self.encrypter.clone())?;
        }

        pubs = nsigners.iter().map(|s| s.verfer.qb64()).collect();
        let pub_set = PubSet { pubs: pubs.clone() };
        self.ks.pubs.put(&[&ri_key(&pre, ridx)], &pub_set)?;

        if ridx == iridx + 1 {
            // want to set up ps.next at this ridx
            let dt = nowiso8601();
            let mut ps = self.ks.sits.get(&[&pre])?.ok_or_else(|| {
                KERIError::ValueError(format!(
                    "Attempt to rotate nonexistent pre={}.",
                    String::from_utf8_lossy(&pre)
                ))
            })?;

            let nxt = PubLot {
                pubs: pubs.clone(),
                ridx,
                kidx,
                dt,
            };
            ps.nxt = nxt;

            if !self.ks.sits.pin(&[&pre], &ps)? {
                return Err(KERIError::ValueError(format!(
                    "Problem updating pubsit db for pre={}.",
                    String::from_utf8_lossy(&pre)
                )));
            }
        }

        Ok((ipre, verferies))
    }

    pub fn replay(
        &mut self,
        pre: &[u8],
        dcode: Option<&str>,
        advance: Option<bool>,
        erase: Option<bool>,
    ) -> Result<(Vec<Verfer>, Vec<Diger>), KERIError> {
        let dcode = dcode.unwrap_or(mtr_dex::BLAKE3_256);
        let advance = advance.unwrap_or(true);
        let erase = erase.unwrap_or(true);

        // Get prefix parameters
        let pp = self.ks.prms.get(&[pre])?.ok_or_else(|| {
            KERIError::ValueError(format!(
                "Attempt to replay nonexistent pre={}.",
                String::from_utf8_lossy(pre)
            ))
        })?;

        // Get prefix situation
        let mut ps = self.ks.sits.get(&[pre])?.ok_or_else(|| {
            KERIError::ValueError(format!(
                "Attempt to replay nonexistent pre={}.",
                String::from_utf8_lossy(pre)
            ))
        })?;

        // Declare old outside of the advance block so it's available later
        let old_keys_to_erase = if advance {
            // Save the old keys before updating
            let old_keys = ps.old.clone();

            ps.old = Some(ps.new.clone()); // move prior new to old so save previous one step
            ps.new = ps.nxt.clone(); // move prior nxt to new which new is now current signer
            let ridx = ps.new.ridx;
            let kidx = ps.new.kidx;
            let csize = ps.new.pubs.len();

            // Usually when next keys are null then aid is effectively non-transferable
            // but when replaying injected keys reaching null next pub keys or
            // equivalently default empty is the sign that we have reached the
            // end of the replay so need to raise an IndexError
            let pubset = self
                .ks
                .pubs
                .get(&[&ri_key(pre, ridx + 1)])?
                .ok_or_else(|| {
                    KERIError::IndexError(format!(
                        "Invalid replay attempt of pre={} at ridx={}.",
                        String::from_utf8_lossy(pre),
                        ridx
                    ))
                })?;

            let pubs = pubset.pubs.clone(); // create nxt from pubs
            let dt = nowiso8601();
            let nxt = PubLot {
                pubs,
                ridx: ridx + 1,
                kidx: kidx + csize,
                dt,
            };
            ps.nxt = nxt;

            // Return the old keys to potentially erase later
            old_keys
        } else {
            None
        };

        let mut verfers = Vec::new(); // assign verfers from current new was prior nxt
        for pub_key in &ps.new.pubs {
            if !self._seed.is_empty() && self.decrypter.is_none() {
                return Err(KERIError::DecryptError(
                    "Unauthorized decryption attempt. Aeid but no decrypter.".to_string(),
                ));
            }

            let signer = self
                .ks
                .pris
                .get(&[pub_key.as_bytes()], self.decrypter.clone())?
                .ok_or_else(|| {
                    KERIError::ValueError(format!("Missing prikey in db for pubkey={}", pub_key))
                })?;

            verfers.push(signer.verfer);
        }

        // Create digers from next public keys
        let mut digers = Vec::new();
        for pub_key in &ps.nxt.pubs {
            let diger = Diger::from_ser(pub_key.as_bytes(), Some(dcode))?;
            digers.push(diger);
        }

        if advance {
            if !self.ks.sits.pin(&[pre], &ps)? {
                return Err(KERIError::ValueError(format!(
                    "Problem updating pubsit db for pre={}.",
                    String::from_utf8_lossy(pre)
                )));
            }

            // Now we can use old_keys_to_erase since it's in scope
            if erase {
                if let Some(old) = old_keys_to_erase {
                    for pub_key in &old.pubs {
                        self.ks.pris.rem(&[pub_key.as_bytes()])?;
                    }
                }
            }
        }

        Ok((verfers, digers))
    }

    /// Update the aeid (authentication and encryption identifier) and re-encrypt all secrets
    ///
    /// # Parameters
    /// * `aeid` - qb64b of new auth encrypt id (public signing key)
    ///            aeid may match current aeid (no change)
    ///            aeid may be empty (unencrypts and removes aeid)
    ///            aeid may be different and not empty (reencrypts)
    /// * `seed` - qb64b of new seed from which new aeid is derived (private signing key seed)
    ///
    /// # Returns
    /// * `Result<(), KERIError>` - Success or error
    pub fn update_aeid(&mut self, aeid: Vec<u8>, seed: Vec<u8>) -> Result<(), KERIError> {
        let current_aeid = self.aeid();

        // Check that the last current seed matches the last current aeid
        if !current_aeid.is_empty() {
            if self._seed.is_empty()
                || !self
                    .encrypter
                    .as_ref()
                    .ok_or_else(|| {
                        KERIError::AuthError("Current encrypter is missing".to_string())
                    })?
                    .verify_seed(&self._seed)?
            {
                return Err(KERIError::AuthError(format!(
                    "Last seed missing or provided last seed not associated with last aeid={:?}.",
                    current_aeid
                )));
            }
        }

        // Update encrypter based on new aeid
        if !aeid.is_empty() {
            if aeid != current_aeid {
                // Changing to a new aeid, so update encrypter
                let new_encrypter = Encrypter::new(None, None, Some(&aeid.clone()))?;

                // Verify new seed belongs to new aeid
                if seed.is_empty() || !new_encrypter.verify_seed(&seed)? {
                    return Err(KERIError::AuthError(format!(
                        "Seed missing or provided seed not associated with provided aeid={:?}.",
                        aeid
                    )));
                }

                self.encrypter = Some(new_encrypter);
            }
        } else {
            // Changing to empty aeid, so new encrypter is None
            self.encrypter = None;
        }

        // Re-encrypt all secrets with new encrypter

        // Re-encrypt root salt secret
        if let Some(salt) = self.salt() {
            // Automatically decrypted on fetch
            self.set_salt(salt)?;
        }

        // Re-encrypt other secrets if we have a decrypter
        if let Some(decrypter) = &self.decrypter {
            // Re-encrypt root salt secrets by prefix parameters in prms
            let empty: [&[u8]; 0] = [];
            for (keys, mut data) in self
                .ks
                .prms
                .get_item_iter(&empty)
                .map_err(|e| KERIError::ManagerError(format!("Failed to update aeid: {}", e)))?
            {
                if !data.salt.is_empty() {
                    // Decrypt the salt with current decrypter
                    let salter_any = decrypter.decrypt(
                        None,
                        Some(&data.salt),
                        None,
                        Some(false),
                        Some(false),
                    )?;
                    let salter = salter_any.downcast_ref::<Salter>().ok_or_else(|| {
                        KERIError::ValueError("Failed to downcast to Salter".to_string())
                    })?;

                    // Re-encrypt with the new encrypter or store as is
                    if let Some(encrypter) = &self.encrypter {
                        let encrypted = encrypter.encrypt(None, Some(salter), None)?;
                        data.salt = encrypted.qb64();
                    } else {
                        data.salt = salter.qb64();
                    }

                    // Update the database
                    self.ks.prms.pin(&keys, &data).map_err(|e| {
                        KERIError::ManagerError(format!("Failed to update aeid: {}", e))
                    })?;
                }
            }

            // Re-encrypt private signing key seeds
            // For each signer in the pris database
            let empty: [&[u8]; 0] = [];
            for (keys, signer) in self
                .ks
                .pris
                .get_item_iter(&empty, false, Some(decrypter.clone()))
                .map_err(|e| KERIError::ManagerError(format!("Failed to update aeid: {}", e)))?
            {
                // Pin the signer with the new encrypter
                self.ks
                    .pris
                    .pin(&keys, &signer, self.encrypter.clone())
                    .map_err(|e| {
                        KERIError::ManagerError(format!("Failed to update aeid: {}", e))
                    })?;
            }
        }

        // Update aeid in database
        self.ks
            .gbls
            .pin(&["aeid"], &aeid)
            .map_err(|e| KERIError::ManagerError(format!("Failed to update aeid: {}", e)))?;

        // Update seed in memory
        self._seed = seed.clone();

        // Update decrypter
        if !seed.is_empty() {
            self.decrypter = Some(Decrypter::new(None, None, Some(&seed))?);
        } else {
            self.decrypter = None;
        }

        Ok(())
    }

    /// Get the aeid (authentication and encryption identifier)
    ///
    /// # Returns
    /// * String - The aeid value
    pub fn aeid(&self) -> Vec<u8> {
        match self.ks.gbls.get(&["aeid"]) {
            Ok(Some(bytes)) => bytes,
            _ => Vec::new(),
        }
    }

    /// Get the pidx (prefix index)
    ///
    /// # Returns
    /// * Option<usize> - The pidx value if it exists
    pub fn pidx(&self) -> Option<usize> {
        match self.ks.gbls.get(&["pidx"]) {
            Ok(Some(bytes)) => {
                let s = String::from_utf8(bytes).unwrap_or_default();
                s.parse::<usize>().ok()
            }
            _ => None,
        }
    }

    /// Set the pidx (prefix index)
    ///
    /// # Parameters
    /// * `value` - New pidx value
    ///
    /// # Returns
    /// * `Result<(), DBError>` - Success or error
    pub fn set_pidx(&self, value: usize) -> Result<(), KERIError> {
        self.ks
            .gbls
            .pin(&["pidx"], &value.to_string().as_bytes())
            .map_err(|e| KERIError::ManagerError(format!("Failed to set pidx: {}", e)))?;
        Ok(())
    }

    /// Get the algo (algorithm)
    ///
    /// # Returns
    /// * Option<String> - The algo value if it exists
    pub fn algo(&self) -> Option<String> {
        match self.ks.gbls.get(&["algo"]) {
            Ok(Some(bytes)) => Some(String::from_utf8(bytes).unwrap_or_default()),
            _ => None,
        }
    }

    /// Set the algo (algorithm)
    ///
    /// # Parameters
    /// * `value` - New algo value
    ///
    /// # Returns
    /// * `Result<(), DBError>` - Success or error
    pub fn set_algo(&self, value: Algos) -> Result<(), KERIError> {
        self.ks
            .gbls
            .pin(&["algo"], &value.to_string().as_bytes())
            .map_err(|e| KERIError::ManagerError(format!("Failed to set algo: {}", e)))?;
        Ok(())
    }

    /// Get the salt
    ///
    /// # Returns
    /// * Option<String> - The salt value if it exists
    pub fn salt(&self) -> Option<Vec<u8>> {
        match self.ks.gbls.get(&["salt"]) {
            Ok(Some(bytes)) => match self.decrypter {
                Some(_) => {
                    let st = String::from_utf8(bytes);
                    let salter = self
                        .decrypter
                        .clone()?
                        .decrypt(None, Some(st.unwrap().as_str()), None, None, None)
                        .unwrap();
                    let salter = salter.downcast_ref::<Salter>().unwrap();
                    Some(salter.qb64b())
                }
                None => Some(bytes),
            },
            _ => None,
        }
    }

    /// Set the salt
    ///
    /// # Parameters
    /// * `value` - New salt value
    ///
    /// # Returns
    /// * `Result<(), KERIError>` - Success or error
    pub fn set_salt(&self, value: Vec<u8>) -> Result<(), KERIError> {
        if let Some(encrypter) = &self.encrypter {
            // Re-encrypt salt with new encrypter
            let encrypted_salt =
                encrypter.encrypt(Some(&value), None, Some(mtr_dex::X25519_CIPHER_SALT))?;
            self.ks
                .gbls
                .pin(&["salt"], &encrypted_salt.qb64b())
                .map_err(|e| KERIError::ManagerError(format!("Failed to set salt: {}", e)))?;
        } else {
            self.ks
                .gbls
                .pin(&["salt"], &value)
                .map_err(|e| KERIError::ManagerError(format!("Failed to set salt: {}", e)))?;
        }

        Ok(())
    }

    /// Get the tier
    ///
    /// # Returns
    /// * Option<String> - The tier value if it exists
    pub fn tier(&self) -> Option<Tiers> {
        match self.ks.gbls.get(&["tier"]) {
            Ok(Some(bytes)) => Some(Tiers::from(
                String::from_utf8(bytes).unwrap_or_default().as_str(),
            )),
            _ => None,
        }
    }

    /// Set the tier
    ///
    /// # Parameters
    /// * `value` - New tier value
    ///
    /// # Returns
    /// * `Result<(), DBError>` - Success or error
    pub fn set_tier(&self, value: Tiers) -> Result<(), KERIError> {
        self.ks
            .gbls
            .put(&["tier"], &value.to_string().as_bytes())
            .map_err(|e| KERIError::ManagerError(format!("Failed to set tier: {}", e)))?;
        Ok(())
    }

    /// Get the seed
    ///
    /// # Returns
    /// * String - The seed value
    pub fn seed(&self) -> &Vec<u8> {
        &self._seed
    }

    /// Incept a prefix with key parameters
    ///
    /// # Parameters
    /// * `icodes` - Optional list of private key derivation codes qb64 str, one per incepting key pair
    /// * `icount` - Count of incepting public keys when icodes not provided
    /// * `icode` - Derivation code of all icount incepting private keys when icodes list not provided
    /// * `ncodes` - Optional list of private key derivation codes qb64 str, one per next key pair
    /// * `ncount` - Count of next public keys when ncodes not provided
    /// * `ncode` - Derivation code of all ncount next private keys when ncodes list not provided
    /// * `dcode` - Derivation code of next digesters. Default is Blake3_256
    /// * `algo` - Optional key creation algorithm code
    /// * `salt` - Optional qb64 salt for randomization when salty algorithm used
    /// * `stem` - Optional path modifier used with salt to derive private keys when using salty algorithm
    /// * `tier` - Optional security criticality tier code when using salty algorithm
    /// * `rooted` - Whether to derive incept salt from root salt when incept salt not provided
    /// * `transferable` - Whether each public key uses transferable derivation code
    /// * `temp` - Whether the inception is temporary for testing, modifies tier of salty algorithm
    ///
    /// # Returns
    /// * `Result<(Vec<Verfer>, Vec<Diger>), KERIError>` - Tuple containing:
    ///   - Vector of current public key verfers
    ///   - Vector of next public key digesters
    pub fn incept(
        &mut self,
        icodes: Option<Vec<&str>>,
        icount: Option<usize>,
        icode: Option<&str>,
        ncodes: Option<Vec<&str>>,
        ncount: Option<usize>,
        ncode: Option<&str>,
        dcode: Option<String>,
        algo: Option<Algos>,
        salt: Option<Vec<u8>>,
        stem: Option<&str>,
        tier: Option<Tiers>,
        rooted: Option<bool>,
        transferable: Option<bool>,
        temp: Option<bool>,
    ) -> Result<(Vec<Verfer>, Vec<Diger>), KERIError> {
        // Set default values
        let rooted = rooted.unwrap_or(true);
        let transferable = transferable.unwrap_or(true);
        let temp = temp.unwrap_or(false);
        let icount = icount.unwrap_or(1);
        let ncount = ncount.unwrap_or(1);
        let icode = icode.unwrap_or_else(|| mtr_dex::ED25519_SEED);
        let ncode = ncode.unwrap_or_else(|| mtr_dex::ED25519_SEED);
        let _dcode = dcode.unwrap_or_else(|| mtr_dex::BLAKE3_256.to_string());

        // Get root defaults to initialize key sequence
        let algo = if rooted && algo.is_none() {
            // Use root algo from db as default
            Algos::from_str(&self.algo().ok_or_else(|| {
                KERIError::ValueError("Root algorithm not found in database".to_string())
            })?)?
        } else {
            algo.unwrap_or(Algos::Salty)
        };

        let salt = if rooted && salt.is_none() {
            // Use root salt from db instead of random salt
            self.salt().ok_or_else(|| {
                KERIError::ValueError("Root salt not found in database".to_string())
            })?
        } else {
            salt.unwrap_or_else(|| Vec::new())
        };

        let tier = if rooted && tier.is_none() {
            // Use root tier from db as default
            &self.tier()
        } else {
            &Some(tier.unwrap_or(Tiers::LOW))
        };

        // Get next pidx
        let pidx = self.pidx().ok_or_else(|| {
            KERIError::ValueError("Prefix index not found in database".to_string())
        })?;
        let ridx = 0; // rotation index
        let kidx = 0; // key pair index

        // Create the key creator
        let creator = Creatory::new(algo).make(
            Some(String::from_utf8(salt).unwrap().as_str()),
            stem.clone(),
            tier.clone(),
        )?;

        // Create initial signers
        let icodes = if let Some(ic) = icodes {
            ic
        } else {
            // Create a vector of the same code with length icount
            (0..icount).map(|_| icode).collect()
        };

        let icode_count = icodes.len();
        let isigners = creator.create(
            Some(icodes),
            None,
            None,
            Some(pidx),
            Some(ridx),
            Some(kidx),
            Some(transferable),
            Some(temp),
        );

        let verfers: Vec<Verfer> = isigners.iter().map(|s| s.verfer.clone()).collect();

        // Create next signers
        let ncodes = if let Some(nc) = ncodes {
            nc
        } else {
            // Create a vector of the same code with length ncount
            (0..ncount).map(|_| ncode).collect()
        };

        let nsigners = creator.create(
            Some(ncodes),
            Some(0), // count set to 0 to ensure does not create signers if ncodes is empty
            None,
            Some(pidx),
            Some(ridx + 1),
            Some(kidx + icode_count),
            Some(transferable),
            Some(temp),
        );

        // Create digesters for next keys
        let digers: Vec<Diger> = nsigners
            .iter()
            .map(|signer| -> Result<Diger, KERIError> {
                Diger::from_ser(&mut signer.verfer.qb64b(), None)
                    .map_err(|e| KERIError::MatterError(e.to_string()))
            })
            .collect::<Result<Vec<Diger>, KERIError>>()?;

        let tier_str = match creator.tier() {
            None => "",
            Some(tier) => &tier.to_string(),
        };
        // Create prefix parameters
        let mut pp = PrePrm {
            pidx,
            algo: algo.to_string(),
            stem: creator.stem().clone(),
            tier: tier_str.to_string(),
            salt: String::new(),
        };

        if !creator.salt().is_empty() {
            if let Some(encrypter) = &self.encrypter {
                // Encrypt the salt
                let cipher = encrypter.encrypt(
                    Some(&creator.salt().as_bytes().to_vec()),
                    None,
                    Some(mtr_dex::X25519_CIPHER_SALT),
                )?;
                pp.salt = cipher.qb64();
            } else {
                // Store salt unencrypted
                pp.salt = String::from_utf8_lossy(&creator.salt().as_bytes().to_vec()).to_string();
            }
        }

        // Get current datetime

        let dt = Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();

        // Create prefix situation
        let ps = PreSit {
            old: None,
            new: PubLot {
                pubs: verfers.iter().map(|v| v.qb64()).collect(),
                ridx,
                kidx,
                dt: dt.clone(),
            },
            nxt: PubLot {
                pubs: nsigners.iter().map(|s| s.verfer.qb64()).collect(),
                ridx: ridx + 1,
                kidx: kidx + icode_count,
                dt,
            },
        };

        // Use first public key as temporary prefix
        let pre = verfers[0].qb64b();

        // Check if prefix already exists
        let pre_exists = self.ks.pres.get(&[&pre])?;
        if pre_exists.is_some() {
            return Err(KERIError::ValueError(format!(
                "Already incepted pre={}.",
                String::from_utf8_lossy(&pre)
            )));
        }

        // Store the prefix
        let prefixer = Prefixer::from_qb64b(&mut pre.clone(), None)?;
        self.ks
            .pres
            .put(&[&pre], &prefixer)
            .map_err(|e| KERIError::ManagerError(format!("Failed to update pres: {}", e)))?;

        // Store the parameters
        if !self.ks.prms.put(&[&pre], &pp)? {
            return Err(KERIError::ValueError(format!(
                "Already incepted prm for pre={}.",
                String::from_utf8_lossy(&pre)
            )));
        }

        // Increment the pidx for next inception
        self.set_pidx(pidx + 1)?;

        // Store the situation
        if !self.ks.sits.put(&[&pre], &ps)? {
            return Err(KERIError::ValueError(format!(
                "Already incepted sit for pre={}.",
                String::from_utf8_lossy(&pre)
            )));
        }

        // Store initial signers (private keys) keyed by public keys
        for signer in isigners {
            self.ks
                .pris
                .put(&[&signer.verfer.qb64b()], &signer, self.encrypter.clone())
                .map_err(|e| KERIError::ManagerError(format!("Failed to put pris: {}", e)))?;
        }

        // Store public keys for initial rotation
        self.ks
            .pubs
            .put(
                &[&Keeper::ri_key(
                    String::from_utf8(pre.clone()).unwrap().as_str(),
                    ridx as u64,
                )],
                &PubSet { pubs: ps.new.pubs },
            )
            .map_err(|e| KERIError::ManagerError(format!("Failed to update pubs: {}", e)))?;

        // Store next signers
        for signer in nsigners {
            self.ks
                .pris
                .put(&[&signer.verfer.qb64b()], &signer, self.encrypter.clone())
                .map_err(|e| KERIError::ManagerError(format!("Failed to put pris: {}", e)))?;
        }

        // Store public keys for next rotation
        self.ks
            .pubs
            .put(
                &[&Keeper::ri_key(
                    String::from_utf8(pre).unwrap().as_str(),
                    (ridx + 1) as u64,
                )],
                &PubSet { pubs: ps.nxt.pubs },
            )
            .map_err(|e| KERIError::ManagerError(format!("Failed to put pubs: {}", e)))?;

        Ok((verfers, digers))
    }

    pub fn move_prefix(&self, old: &[u8], new: &[u8]) -> Result<(), KERIError> {
        // If old and new are the same, nothing to do
        if old == new {
            return Ok(());
        }

        // Check if old prefix exists
        let old_pre = self.ks.pres.get(&[old])?;
        if old_pre.is_none() {
            return Err(KERIError::ValueError(format!(
                "Nonexistent old pre={}, nothing to assign.",
                String::from_utf8_lossy(old)
            )));
        }

        // Check if new prefix already exists (to avoid clobbering)
        let new_pre = self.ks.pres.get(&[new])?;
        if new_pre.is_some() {
            return Err(KERIError::ValueError(format!(
                "Preexistent new pre={} may not clobber.",
                String::from_utf8_lossy(new)
            )));
        }

        // Get old PrePrm
        let old_prm = self.ks.prms.get(&[old])?;
        if old_prm.is_none() {
            return Err(KERIError::ValueError(format!(
                "Nonexistent old prm for pre={}, nothing to move.",
                String::from_utf8_lossy(old)
            )));
        }
        let old_prm = old_prm.unwrap();

        // Check if new PrePrm already exists
        let new_prm = self.ks.prms.get(&[new])?;
        if new_prm.is_some() {
            return Err(KERIError::ValueError(format!(
                "Preexistent new prm for pre={} may not clobber.",
                String::from_utf8_lossy(new)
            )));
        }

        // Get old PreSit
        let old_sit = self.ks.sits.get(&[old])?;
        if old_sit.is_none() {
            return Err(KERIError::ValueError(format!(
                "Nonexistent old sit for pre={}, nothing to move.",
                String::from_utf8_lossy(old)
            )));
        }
        let old_sit = old_sit.unwrap();

        // Check if new PreSit already exists
        let new_sit = self.ks.sits.get(&[new])?;
        if new_sit.is_some() {
            return Err(KERIError::ValueError(format!(
                "Preexistent new sit for pre={} may not clobber.",
                String::from_utf8_lossy(new)
            )));
        }

        // Move PrePrm
        if !self.ks.prms.put(&[new], &old_prm)? {
            return Err(KERIError::ValueError(format!(
                "Failed moving prm from old pre={} to new pre={}.",
                String::from_utf8_lossy(old),
                String::from_utf8_lossy(new)
            )));
        } else {
            self.ks.prms.rem(&[old])?;
        }

        // Move PreSit
        if !self.ks.sits.put(&[new], &old_sit)? {
            return Err(KERIError::ValueError(format!(
                "Failed moving sit from old pre={} to new pre={}.",
                String::from_utf8_lossy(old),
                String::from_utf8_lossy(new)
            )));
        } else {
            self.ks.sits.rem(&[old])?;
        }

        // Move .pubs entries if any
        let mut i: u64 = 0;
        let old_str = String::from_utf8_lossy(old).to_string();
        let new_str = String::from_utf8_lossy(new).to_string();

        while let Some(pl) = self.ks.pubs.get(&[&Keeper::ri_key(&old_str, i)])? {
            if !self.ks.pubs.put(&[&Keeper::ri_key(&new_str, i)], &pl)? {
                return Err(KERIError::ValueError(format!(
                    "Failed moving pubs at pre={} ri={} to new pre={}",
                    old_str, i, new_str
                )));
            }
            // Remove the old pubkey entry
            self.ks.pubs.rem(&[&Keeper::ri_key(&old_str, i)])?;
            i += 1;
        }

        // Create a Prefixer from the new prefix
        let mut new_copy = new.to_vec();
        let new_prefixer = Prefixer::from_qb64b(&mut new_copy, None)?;

        // Assign old (replace with new prefixer)
        if !self.ks.pres.pin(&[old], &new_prefixer)? {
            return Err(KERIError::ValueError(format!(
                "Failed assigning new pre={} to old pre={}.",
                String::from_utf8_lossy(new),
                String::from_utf8_lossy(old)
            )));
        }

        // Make new entry to reserve prefix
        if !self.ks.pres.put(&[new], &new_prefixer)? {
            return Err(KERIError::ValueError(format!(
                "Failed assigning new pre={}.",
                String::from_utf8_lossy(new)
            )));
        }

        Ok(())
    }

    /// Rotates keys for a prefix and returns tuple of verfers and digers
    ///
    /// Returns tuple (verfers, digers) for rotation event of keys for pre where
    /// verfers is list of current public key verfers
    /// public key is verfer.qb64
    /// digers is list of next public key digers
    /// digest to xor is diger.raw
    ///
    /// Rotates a prefix.
    /// Store the updated dictified PreSit in the keeper under pre
    ///
    /// # Parameters
    /// * `pre` - qb64b of prefix to rotate
    /// * `ncodes` - Optional list of private key derivation codes (qb64 string refs)
    ///   one per next key pair
    /// * `ncount` - Count of next public keys when ncodes not provided
    /// * `ncode` - Derivation code qb64 of all ncount next private keys
    ///   when ncodes not provided
    /// * `dcode` - Derivation code qb64 of next key digest of digers
    ///   Default is mtr_dex::BLAKE3_256
    /// * `transferable` - True means each public key uses transferable derivation code
    ///   Default is transferable. Special case is non-transferable.
    ///   Normally no use case for rotation to use transferable = False.
    ///   When the derivation process of the identifier prefix is
    ///   transferable then one should not use transferable = False for the
    ///   associated public key(s).
    /// * `temp` - True is temporary for testing. It modifies tier of salty algorithm
    /// * `erase` - True means erase old private keys made stale by rotation
    ///
    /// When both ncodes is empty and ncount is 0 then the nxt is null and will
    /// not be rotatable. This makes the identifier non-transferable in effect
    /// even when the identifier prefix is transferable.
    ///
    /// # Returns
    /// * `Result<(Vec<Verfer>, Vec<Diger>), KERIError>` - Tuple containing:
    ///   - Vector of current public key verfers
    ///   - Vector of next public key digers
    pub fn rotate(
        &self,
        pre: &[u8],
        ncodes: Option<Vec<&str>>,
        ncount: Option<usize>,
        ncode: Option<&str>,
        dcode: Option<&str>,
        transferable: Option<bool>,
        temp: Option<bool>,
        erase: Option<bool>,
    ) -> Result<(Vec<Verfer>, Vec<Diger>), KERIError> {
        // Set default values
        let ncount = ncount.unwrap_or(1);
        let ncode = ncode.unwrap_or(mtr_dex::ED25519_SEED);
        let _dcode = dcode.unwrap_or(mtr_dex::BLAKE3_256);
        let transferable = transferable.unwrap_or(true);
        let temp = temp.unwrap_or(false);
        let erase = erase.unwrap_or(true);

        // Get prefix parameters from database
        let pp = match self.ks.prms.get(&[pre])? {
            Some(pp) => pp,
            None => {
                return Err(KERIError::ValueError(format!(
                    "Attempt to rotate nonexistent pre={}.",
                    String::from_utf8_lossy(pre)
                )))
            }
        };

        // Get prefix situation from database
        let mut ps = match self.ks.sits.get(&[pre])? {
            Some(ps) => ps,
            None => {
                return Err(KERIError::ValueError(format!(
                    "Attempt to rotate nonexistent pre={}.",
                    String::from_utf8_lossy(pre)
                )))
            }
        };

        // Check if the prefix is transferable (has next public keys)
        if ps.nxt.pubs.is_empty() {
            return Err(KERIError::ValueError(format!(
                "Attempt to rotate nontransferable pre={}.",
                String::from_utf8_lossy(pre)
            )));
        }

        // Save the old keys for potential cleanup
        let old = ps.old.clone();

        // Move prior new to old so save previous one step
        ps.old = Some(ps.new.clone());

        // Move prior nxt to new which is now current signer
        ps.new = ps.nxt.clone();

        // Assign verfers from current new (was prior nxt)
        let mut verfers = Vec::new();
        for pub_key in &ps.new.pubs {
            // Check for encryption/decryption authorization
            if self.encrypter.is_some() && self.decrypter.is_none() {
                return Err(KERIError::AuthError(
                    "Unauthorized decryption attempt. Aeid but no decrypter.".to_string(),
                ));
            }

            // Get the signer from the database
            let signer = match self
                .ks
                .pris
                .get(&[pub_key.as_bytes()], self.decrypter.clone())?
            {
                Some(signer) => signer,
                None => {
                    return Err(KERIError::ValueError(format!(
                        "Missing prikey in db for pubkey={}",
                        pub_key
                    )))
                }
            };

            verfers.push(signer.verfer);
        }

        // Process salt - decrypt if necessary
        let salt = if !pp.salt.is_empty() {
            if self.encrypter.is_some() {
                // We need to decrypt the salt
                if self.decrypter.is_none() {
                    return Err(KERIError::AuthError(
                        "Unauthorized decryption. Aeid but no decrypter.".to_string(),
                    ));
                }

                // Decrypt the salt
                let salter_any = self.decrypter.as_ref().unwrap().decrypt(
                    None,
                    Some(&pp.salt),
                    None,
                    None,
                    None,
                )?;

                let salter = salter_any.downcast_ref::<Salter>().ok_or_else(|| {
                    KERIError::ValueError("Failed to downcast to Salter".to_string())
                })?;

                salter.qb64()
            } else {
                // Salt is not encrypted, just ensure it's valid
                let mut salt_bytes = pp.salt.as_bytes().to_vec();
                let salter = Salter::from_qb64b(&mut salt_bytes, None)?;
                salter.qb64()
            }
        } else {
            String::new()
        };

        // Create key creator
        let creator = Creatory::new(Algos::from_str(&pp.algo)?).make(
            Some(&salt),
            Some(&pp.stem),
            Some(Tiers::from(pp.tier.as_str())),
        )?;

        // Process ncodes
        let ncodes_to_use = if let Some(codes) = ncodes {
            codes
        } else {
            // Create vector with ncount copies of ncode
            vec![ncode; ncount]
        };

        // Set up parameters for creating next keys
        let pidx = pp.pidx;
        let ridx = ps.new.ridx + 1;
        let kidx = ps.nxt.kidx + ps.new.pubs.len();

        // Create next signers
        // Count set to 0 to ensure does not create signers if codes is empty
        let signers = creator.create(
            Some(ncodes_to_use),
            Some(0),
            None,
            Some(pidx),
            Some(ridx),
            Some(kidx),
            Some(transferable),
            Some(temp),
        );

        // Create digesters for next keys
        let digers = signers
            .iter()
            .map(|signer| -> Result<Diger, KERIError> {
                Diger::from_ser(&mut signer.verfer.qb64b(), None)
                    .map_err(|e| KERIError::MatterError(e.to_string()))
            })
            .collect::<Result<Vec<Diger>, KERIError>>()?;

        // Create the new next key set with current timestamp
        let dt = Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();
        ps.nxt = PubLot {
            pubs: signers.iter().map(|signer| signer.verfer.qb64()).collect(),
            ridx,
            kidx,
            dt,
        };

        // Update the prefix situation in the database
        if !self.ks.sits.pin(&[pre], &ps)? {
            return Err(KERIError::ValueError(format!(
                "Problem updating pubsit db for pre={}.",
                String::from_utf8_lossy(pre)
            )));
        }

        // Store the new signers' private keys
        for signer in &signers {
            self.ks
                .pris
                .put(&[&signer.verfer.qb64b()], signer, self.encrypter.clone())?;
        }

        // Store public keys for lookup by rotation index
        let pre_str = String::from_utf8_lossy(pre).to_string();
        self.ks.pubs.put(
            &[&Keeper::ri_key(&pre_str, ps.nxt.ridx as u64)],
            &PubSet { pubs: ps.nxt.pubs },
        )?;

        // Erase old private keys if requested
        if erase && old.is_some() {
            if let Some(old_keys) = old {
                for pub_key in old_keys.pubs {
                    self.ks.pris.rem(&[pub_key.as_bytes()])?;
                }
            }
        }

        Ok((verfers, digers))
    }

    /// Signs serialized data using private keys looked up from public keys
    ///
    /// # Parameters
    /// * `ser` - Serialized data to sign
    /// * `pubs` - Optional list of qb64 public keys to lookup private keys
    ///   one of pubs or verfers is required. If both then verfers is ignored.
    /// * `verfers` - Optional list of Verfer instances of public keys
    ///   one of pubs or verfers is required. If both then verfers is ignored.
    ///   If not pubs then gets public key from verfer.qb64
    /// * `indexed` - True means use indexed signatures and return list of Siger instances.
    ///   False means do not use indexed signatures and return list of Cigar instances
    /// * `indices` - Optional list of indices (offsets) when indexed == true,
    ///   to use for indexed signatures whose offset into the current keys
    ///   or prior next list may differ from the order of appearance
    ///   in the provided coherent pubs, verfers, signers lists.
    /// * `ondices` - Optional list of other indices (offsets) when indexed is true
    ///   for indexed signatures whose offset into the prior next list may differ
    ///   from the order of appearance in the provided coherent lists.
    /// * `pre` - Optional identity prefix (aid) of signer. Used for HDK salty
    ///   algo key lookup or re-creation.
    /// * `path` - Optional HDX randy algo signing key path tuple part
    ///
    /// # Returns
    /// * `Result<Vec<Siger>, KERIError>` - List of Siger instances if indexed is true
    /// * `Result<Vec<Cigar>, KERIError>` - List of Cigar instances if indexed is false
    ///
    /// # Notes
    /// When indexed, each index is an offset that maps the offset
    /// in the coherent lists onto the appropriate offset into
    /// the signing keys or prior next keys lists of a key event.
    pub fn sign(
        &self,
        ser: &[u8],
        pubs: Option<Vec<String>>,
        verfers: Option<Vec<Verfer>>,
        indexed: Option<bool>,
        indices: Option<Vec<u32>>,
        ondices: Option<Vec<Option<u32>>>,
        pre: Option<&[u8]>,
        _path: Option<(usize, usize)>,
    ) -> Result<Vec<Sigmat>, KERIError> {
        // Set default values
        let indexed = indexed.unwrap_or(true);

        let mut signers = Vec::new();

        // Handle case when both pubs and verfers are None
        if pubs.is_none() && verfers.is_none() {
            if pre.is_none() {
                return Err(KERIError::ValueError(
                    "pubs or verfers or pre required".to_string(),
                ));
            }

            // Logic for generating signers from pre and path would go here
            // This part of the Python code is marked as placeholders/TODOs
            // For now, we'll leave this as unimplemented
            unimplemented!()
        }

        // Process pubs if provided
        if let Some(pub_keys) = pubs {
            for pub_key in pub_keys {
                // Check if we need decryption but don't have a decrypter
                if self.encrypter.is_some() && self.decrypter.is_none() {
                    return Err(KERIError::AuthError(
                        "Unauthorized decryption attempt. Aeid but no decrypter.".to_string(),
                    ));
                }

                // Get the signer from private keys database
                let signer = self
                    .ks
                    .pris
                    .get(&[pub_key.as_bytes()], self.decrypter.clone())?
                    .ok_or_else(|| {
                        KERIError::ValueError(format!(
                            "Missing prikey in db for pubkey={}",
                            pub_key
                        ))
                    })?;

                signers.push(signer);
            }
        }
        // Process verfers if provided and pubs was not provided
        else if let Some(verfer_list) = verfers {
            for verfer in verfer_list {
                // Check if we need decryption but don't have a decrypter
                if self.encrypter.is_some() && self.decrypter.is_none() {
                    return Err(KERIError::AuthError(
                        "Unauthorized decryption attempt. Aeid but no decrypter.".to_string(),
                    ));
                }

                // Get the signer from private keys database
                let signer = self
                    .ks
                    .pris
                    .get(&[verfer.qb64b().as_slice()], self.decrypter.clone())?
                    .ok_or_else(|| {
                        KERIError::ValueError(format!(
                            "Missing prikey in db for pubkey={}",
                            verfer.qb64()
                        ))
                    })?;

                signers.push(signer);
            }
        }

        // Validate indices length if provided
        if let Some(ref idx) = indices {
            if idx.len() != signers.len() {
                return Err(KERIError::ValueError(format!(
                    "Mismatch indices length={} and resultant signers length={}",
                    idx.len(),
                    signers.len()
                )));
            }
        }

        // Validate ondices length if provided
        if let Some(ref odx) = ondices {
            if odx.len() != signers.len() {
                return Err(KERIError::ValueError(format!(
                    "Mismatch ondices length={} and resultant signers length={}",
                    odx.len(),
                    signers.len()
                )));
            }
        }

        // Create signatures based on indexed flag
        if indexed {
            let mut sigers = Vec::with_capacity(signers.len());

            for j in 0..signers.len() {
                // Determine index value
                let i = if let Some(ref idx) = indices {
                    // Use provided index
                    idx[j]
                } else {
                    // Default to position in signers list
                    j as u32
                };

                // Determine ondex value
                let o = if let Some(ref odx) = ondices {
                    // Use provided ondex
                    odx[j]
                } else {
                    // Default to None (no ondex)
                    Some(i)
                };

                // Create siger with appropriate parameters
                let siger = signers[j].sign(
                    ser,
                    Some(i),
                    Some(o.is_none()), // only = true if o is None
                    o,
                )?;

                sigers.push(siger);
            }

            Ok(sigers)
        } else {
            // For non-indexed signatures, create cigars
            let mut cigars = Vec::with_capacity(signers.len());

            for signer in signers {
                let cigar = signer.sign(ser, None, None, None)?;
                cigars.push(cigar);
            }

            Ok(cigars)
        }
    }

    /// Returns decrypted plaintext of encrypted qb64 ciphertext serialization.
    ///
    /// # Parameters
    /// * `qb64` - Fully qualified base64 ciphertext serialization to decrypt
    /// * `pubs` - Optional list of qb64 public keys to lookup private keys
    ///   one of pubs or verfers is required. If both then verfers is ignored.
    /// * `verfers` - Optional list of Verfer instances of public keys
    ///   one of pubs or verfers is required. If both then verfers is ignored.
    ///   If not pubs then gets public key from verfer.qb64 used to lookup
    ///   private keys
    ///
    /// # Returns
    /// * `Result<Vec<u8>, KERIError>` - Decrypted plaintext or error
    pub fn decrypt(
        &self,
        qb64: &[u8],
        pubs: Option<Vec<&str>>,
        verfers: Option<Vec<Verfer>>,
    ) -> Result<Vec<u8>, KERIError> {
        let mut signers = Vec::new();

        // Handle pubs if provided
        if let Some(pub_keys) = pubs {
            for pub_key in pub_keys {
                // Check if we need decryption but don't have a decrypter
                if self.encrypter.is_some() && self.decrypter.is_none() {
                    return Err(KERIError::DecryptError(
                        "Unauthorized decryption attempt. Aeid but no decrypter.".to_string(),
                    ));
                }

                // Get the signer from private keys database
                let signer = self
                    .ks
                    .pris
                    .get(&[pub_key.as_bytes()], self.decrypter.clone())?
                    .ok_or_else(|| {
                        KERIError::ValueError(format!(
                            "Missing prikey in db for pubkey={}",
                            pub_key
                        ))
                    })?;

                signers.push(signer);
            }
        }
        // Process verfers if provided and pubs was not provided
        else if let Some(verfer_list) = verfers {
            for verfer in verfer_list {
                // Check if we need decryption but don't have a decrypter
                if self.encrypter.is_some() && self.decrypter.is_none() {
                    return Err(KERIError::DecryptError(
                        "Unauthorized decryption attempt. Aeid but no decrypter.".to_string(),
                    ));
                }

                // Get the signer from private keys database
                let signer = self
                    .ks
                    .pris
                    .get(&[verfer.qb64b().as_slice()], self.decrypter.clone())?
                    .ok_or_else(|| {
                        KERIError::ValueError(format!(
                            "Missing prikey in db for pubkey={}",
                            verfer.qb64()
                        ))
                    })?;

                signers.push(signer);
            }
        } else {
            return Err(KERIError::ValueError(
                "Either pubs or verfers must be provided".to_string(),
            ));
        }

        // Convert the input to bytes
        let qb64b = qb64.to_vec();
        let mut plain = Vec::new();

        // Try decryption with each signer
        for signer in signers {
            // Combine the raw seed and raw verification key to create the signing key
            let mut sigkey = Vec::with_capacity(signer.raw().len() + signer.verfer().raw().len());
            sigkey.extend_from_slice(signer.raw());
            sigkey.extend_from_slice(signer.verfer().raw());

            // Convert the signing key to a private encryption key (using sodium)
            let prikey = sodiumoxide::crypto::sign::ed25519::to_curve25519_sk(
                &SecretKey::from_slice(&sigkey).unwrap(),
            )
            .unwrap();

            // Derive the public key from the private key
            let pubkey = prikey.public_key();

            // Attempt to decrypt using the sealed box
            match sodiumoxide::crypto::sealedbox::open(&qb64b, &pubkey, &prikey) {
                Ok(decrypted) => {
                    plain = decrypted;
                    break;
                }
                Err(_) => continue, // Try the next signer if this one fails
            }
        }

        // If the plain text is the same as the input, decryption failed
        if plain == qb64b {
            return Err(KERIError::ValueError("Unable to decrypt.".to_string()));
        }

        Ok(plain)
    }

    // TODO: Implement ingest and reply from KERIpy implementations.
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cesr::indexing::Indexer;
    use crate::cesr::signing::{Cipher, Signer};
    use crate::keri::db::dbing::LMDBer;
    use std::sync::Arc;

    #[test]
    fn test_manager_creation() -> Result<(), KERIError> {
        let lmdber = LMDBer::builder()
            .name("manager_ks")
            .reopen(true)
            .build()
            .expect("Failed to open manager database: {}");
        let keeper = Keeper::new(Arc::new(&lmdber)).expect("Failed to create manager database");
        let manager = Manager::new(keeper, None, None, None, None, None, None)?;

        assert!(manager.inited);
        assert!(manager.encrypter.is_none());
        assert!(manager.decrypter.is_none());
        assert!(manager.seed().is_empty());

        Ok(())
    }

    #[test]
    fn test_manager() -> Result<(), KERIError> {
        // Setup with raw salt
        let raw = b"0123456789abcdef".to_vec();
        let salter = Salter::new(Some(&raw), None, None)?;
        let salt = salter.qb64b();
        let stem = "red";

        assert_eq!(salt, b"0AAwMTIzNDU2Nzg5YWJjZGVm");

        // Sample serialization for testing (specific content doesn't matter)
        let ser = br#"{"vs":"KERI10JSON0000fb_","pre":"EvEnZMhz52iTrJU8qKwtDxzmypyosgG70m6LIjkiCdoI","sn":"0","ilk":"icp","sith":"1","keys":["DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA"],"nxt":"EPYuj8mq_PYYsoBKkzX1kxSPGYBWaIya3slgCOyOtlqU","toad":"0","wits":[],"cnfg":[]}-AABAApYcYd1cppVg7Inh2YCslWKhUwh59TrPpIoqWxN2A38NCbTljvmBPBjSGIFDBNOvVjHpdZlty3Hgk6ilF8pVpAQ"#.to_vec();

        // Create a keeper and manager for testing
        let lmdber = LMDBer::builder()
            .name("manager_ks")
            .reopen(true)
            .build()
            .expect("Failed to open manager database: {}");
        let keeper = Keeper::new(Arc::new(&lmdber)).expect("Failed to create manager database");

        // Test invalid salt error
        let result = Manager::new(
            keeper,
            None,
            None,
            None,
            None,
            Some(b"0AzwMTIzNDU2Nzg5YWJjZGVm".to_vec()),
            None,
        );
        assert!(result.is_err());
        assert!(matches!(result, Err(KERIError::MatterError(_))));

        // Create valid manager with salt
        let keeper = Keeper::new(Arc::new(&lmdber)).expect("Failed to create manager database");
        let mut manager = Manager::new(keeper, None, None, None, None, Some(salt.clone()), None)?;

        assert!(manager.ks.opened());
        assert_eq!(manager.pidx(), Some(0));
        assert_eq!(manager.tier(), Some(Tiers::LOW));
        assert_eq!(manager.salt(), Some(salt.clone()));
        assert_eq!(manager.aeid(), Vec::<u8>::new());
        assert_eq!(manager.seed(), &Vec::<u8>::new());
        assert!(manager.encrypter.is_none());
        assert!(manager.decrypter.is_none());

        // Test salty algorithm incept
        let (verfers, digers) = manager.incept(
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(salt.clone()),
            None,
            None,
            None,
            None,
            Some(true),
        )?;

        assert_eq!(verfers.len(), 1);
        assert_eq!(digers.len(), 1);
        assert_eq!(manager.pidx(), Some(1));

        let spre = verfers[0].qb64b();
        assert_eq!(&spre, b"DFRtyHAjSuJaRX6TDPva35GN11VHAruaOXMc79ZYDKsT");

        let pp = manager.ks.prms.get(&[&spre])?.unwrap();
        assert_eq!(pp.pidx, 0);
        assert_eq!(pp.algo, Algos::Salty.to_string());
        assert_eq!(pp.salt, String::from_utf8(salt.clone()).unwrap());
        assert_eq!(pp.stem, "");
        assert_eq!(pp.tier, Tiers::LOW.to_string());

        let ps = manager.ks.sits.get(&[&spre])?.unwrap();
        assert!(ps.old.is_none());
        assert_eq!(ps.new.pubs.len(), 1);
        assert_eq!(
            ps.new.pubs,
            vec!["DFRtyHAjSuJaRX6TDPva35GN11VHAruaOXMc79ZYDKsT"]
        );
        assert_eq!(ps.new.ridx, 0);
        assert_eq!(ps.new.kidx, 0);
        assert_eq!(ps.nxt.pubs.len(), 1);
        assert_eq!(
            ps.nxt.pubs,
            vec!["DHByVjuBrM1D9K71TuE5dq1HVDNS5-aLD-wcIlHiVoXX"]
        );
        assert_eq!(ps.nxt.ridx, 1);
        assert_eq!(ps.nxt.kidx, 1);

        let keys: Vec<String> = verfers.iter().map(|v| v.qb64()).collect();
        assert_eq!(keys, ps.new.pubs);

        // Test .pubs db
        let pl = manager
            .ks
            .pubs
            .get(&[Keeper::ri_key(
                String::from_utf8(spre.clone()).unwrap().as_str(),
                ps.new.ridx as u64,
            )])?
            .unwrap();
        assert_eq!(pl.pubs, ps.new.pubs);

        let pl = manager
            .ks
            .pubs
            .get(&[Keeper::ri_key(
                String::from_utf8(spre.clone()).unwrap().as_str(),
                ps.nxt.ridx as u64,
            )])?
            .unwrap();
        assert_eq!(pl.pubs, ps.nxt.pubs);

        let digs: Vec<String> = digers.iter().map(|d| d.qb64()).collect();
        assert_eq!(digs, vec!["EBhBRqVbqhhP7Ciah5pMIOdsY5Mm1ITm2Fjqb028tylu"]);

        // Test move operation
        let oldspre = spre.clone();
        let spre = b"DCu5o5cxzv1lgMqxMVG3IcCNK4lpFfpMM-9rfkY3XVUc".to_vec();
        manager.move_prefix(&oldspre, &spre)?;

        // Test .pubs db after move
        let pl = manager
            .ks
            .pubs
            .get(&[Keeper::ri_key(
                String::from_utf8(spre.clone()).unwrap().as_str(),
                ps.new.ridx as u64,
            )])?
            .unwrap();
        assert_eq!(pl.pubs, ps.new.pubs);

        let pl = manager
            .ks
            .pubs
            .get(&[Keeper::ri_key(
                String::from_utf8(spre.clone()).unwrap().as_str(),
                ps.nxt.ridx as u64,
            )])?
            .unwrap();
        assert_eq!(pl.pubs, ps.nxt.pubs);

        // Test signing with pubs
        let psigers = manager.sign(
            &ser,
            Some(ps.new.pubs.clone()),
            None,
            None,
            None,
            None,
            None,
            None,
        )?;
        for siger in &psigers {
            match siger {
                Sigmat::Indexed(_) => {}
                _ => panic!("Expected indexed signature"),
            }
        }

        // Test signing with verfers
        let vsigers = manager.sign(
            &ser,
            None,
            Some(verfers.clone()),
            None,
            None,
            None,
            None,
            None,
        )?;

        let psigs: Vec<String> = psigers
            .iter()
            .map(|s| {
                let Sigmat::Indexed(sig) = s else {
                    panic!("Not indexed")
                };
                sig.qb64()
            })
            .collect();
        let vsigs: Vec<String> = vsigers
            .iter()
            .map(|s| {
                let Sigmat::Indexed(sig) = s else {
                    panic!("Not indexed")
                };
                sig.qb64()
            })
            .collect();

        assert_eq!(psigs, vsigs);
        assert_eq!(psigs, vec!["AAAa70b4QnTOtGOsMqcezMtVzCFuRJHGeIMkWYHZ5ZxGIXM0XDVAzkYdCeadfPfzlKC6dkfiwuJ0IzLOElaanUgH"]);

        // Test sign with indices
        let indices = Some(vec![3]);

        // Test with pubs list
        let psigers = manager.sign(
            &ser,
            Some(ps.new.pubs.clone()),
            None,
            None,
            indices.clone(),
            None,
            None,
            None,
        )?;

        match &psigers[0] {
            Sigmat::Indexed(s) => assert_eq!(s.index(), 3),
            _ => panic!("Expected indexed signature"),
        }

        let psigs: Vec<String> = psigers
            .iter()
            .map(|s| {
                let Sigmat::Indexed(sig) = s else {
                    panic!("Not indexed")
                };
                sig.qb64()
            })
            .collect();
        assert_eq!(psigs, vec!["ADAa70b4QnTOtGOsMqcezMtVzCFuRJHGeIMkWYHZ5ZxGIXM0XDVAzkYdCeadfPfzlKC6dkfiwuJ0IzLOElaanUgH"]);

        // Test with verfers list
        let vsigers = manager.sign(
            &ser,
            None,
            Some(verfers.clone()),
            None,
            indices,
            None,
            None,
            None,
        )?;

        match &vsigers[0] {
            Sigmat::Indexed(s) => assert_eq!(s.index(), 3),
            _ => panic!("Expected indexed signature"),
        }

        let vsigs: Vec<String> = vsigers
            .iter()
            .map(|s| {
                let Sigmat::Indexed(sig) = s else {
                    panic!("Not indexed")
                };
                sig.qb64()
            })
            .collect();
        assert_eq!(vsigs, psigs);

        // Test non-indexed signatures (cigars)
        let pcigars = manager.sign(
            &ser,
            Some(ps.new.pubs.clone()),
            None,
            Some(false),
            None,
            None,
            None,
            None,
        )?;
        for cigar in &pcigars {
            match cigar {
                Sigmat::NonIndexed(_) => (),
                _ => panic!("Expected non-indexed signature"),
            }
        }

        let vcigars = manager.sign(
            &ser,
            None,
            Some(verfers.clone()),
            Some(false),
            None,
            None,
            None,
            None,
        )?;

        let psigs: Vec<String> = pcigars
            .iter()
            .map(|s| {
                let Sigmat::NonIndexed(sig) = s else {
                    panic!("Not indexed")
                };
                sig.qb64()
            })
            .collect();
        let vsigs: Vec<String> = vcigars
            .iter()
            .map(|s| {
                let Sigmat::NonIndexed(sig) = s else {
                    panic!("Not indexed")
                };
                sig.qb64()
            })
            .collect();

        assert_eq!(psigs, vsigs);
        assert_eq!(psigs, vec!["0BAa70b4QnTOtGOsMqcezMtVzCFuRJHGeIMkWYHZ5ZxGIXM0XDVAzkYdCeadfPfzlKC6dkfiwuJ0IzLOElaanUgH"]);

        // Test salty algorithm rotate
        let oldpubs: Vec<String> = verfers.iter().map(|v| v.qb64()).collect();
        let (verfers, digers) = manager.rotate(
            &String::from_utf8(spre.clone()).unwrap().as_bytes(),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )?;

        assert_eq!(verfers.len(), 1);
        assert_eq!(digers.len(), 1);

        let pp = manager.ks.prms.get(&[&spre])?.unwrap();
        assert_eq!(pp.pidx, 0);
        assert_eq!(pp.algo, Algos::Salty.to_string());
        assert_eq!(pp.salt, String::from_utf8(salt.clone()).unwrap());
        assert_eq!(pp.stem, "");
        assert_eq!(pp.tier, Tiers::LOW.to_string());

        let ps = manager.ks.sits.get(&[&spre])?.unwrap();
        assert_eq!(
            ps.old.clone().unwrap().pubs,
            vec!["DFRtyHAjSuJaRX6TDPva35GN11VHAruaOXMc79ZYDKsT"]
        );
        assert_eq!(ps.new.pubs.len(), 1);
        assert_eq!(
            ps.new.pubs,
            vec!["DHByVjuBrM1D9K71TuE5dq1HVDNS5-aLD-wcIlHiVoXX"]
        );
        assert_eq!(ps.new.ridx, 1);
        assert_eq!(ps.new.kidx, 1);
        assert_eq!(ps.nxt.pubs.len(), 1);
        assert_eq!(
            ps.nxt.pubs,
            vec!["DAoQ1WxT29XtCFtOpJZyuO2q38BD8KTefktf7X0WN4YW"]
        );
        assert_eq!(ps.nxt.ridx, 2);
        assert_eq!(ps.nxt.kidx, 2);

        let keys: Vec<String> = verfers.iter().map(|v| v.qb64()).collect();
        assert_eq!(keys, ps.new.pubs);

        let digs: Vec<String> = digers.iter().map(|d| d.qb64()).collect();
        assert_eq!(digs, vec!["EJczV8HmnEWZiEHw2lVuSatrvzCmJOZ3zpa7JFfrnjau"]);

        assert_eq!(oldpubs, ps.old.clone().unwrap().pubs);

        // Test salty algorithm rotate again
        let oldpubs: Vec<String> = verfers.iter().map(|v| v.qb64()).collect();
        let deadpubs = ps.old.clone().unwrap().pubs.clone();

        let (_verfers, _digers) = manager.rotate(
            &String::from_utf8(spre.clone()).unwrap().as_bytes(),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )?;

        let pp = manager.ks.prms.get(&[&spre])?.unwrap();
        assert_eq!(pp.pidx, 0);

        let ps = manager.ks.sits.get(&[&spre])?.unwrap();
        assert_eq!(oldpubs, ps.old.unwrap().pubs);

        // Check that old keys are removed
        for pub_key in deadpubs {
            assert!(manager.ks.pris.get(&[pub_key.as_bytes()], None)?.is_none());
        }

        // Test .pubs db
        let pl = manager
            .ks
            .pubs
            .get(&[Keeper::ri_key(
                String::from_utf8(spre.clone()).unwrap().as_str(),
                ps.new.ridx as u64,
            )])?
            .unwrap();
        assert_eq!(pl.pubs, ps.new.pubs);

        let pl = manager
            .ks
            .pubs
            .get(&[Keeper::ri_key(
                String::from_utf8(spre.clone()).unwrap().as_str(),
                ps.nxt.ridx as u64,
            )])?
            .unwrap();
        assert_eq!(pl.pubs, ps.nxt.pubs);

        // Test salty algorithm rotate to null (non-transferable)
        let (_verfers, digers) = manager.rotate(
            &String::from_utf8(spre.clone()).unwrap().as_bytes(),
            None,
            Some(0),
            None,
            None,
            None,
            None,
            None,
        )?;

        let pp = manager.ks.prms.get(&[&spre])?.unwrap();
        assert_eq!(pp.pidx, 0);

        let ps = manager.ks.sits.get(&[&spre])?.unwrap();
        assert!(ps.nxt.pubs.is_empty());
        assert!(digers.is_empty());

        // Test attempt to rotate after null (should fail)
        let result = manager.rotate(
            &String::from_utf8(spre.clone()).unwrap().as_bytes(),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        );

        assert!(result.is_err());
        let err = result.unwrap_err();
        match err {
            KERIError::ValueError(msg) => {
                assert!(msg.starts_with("Attempt to rotate nontransferable"));
            }
            _ => panic!("Expected ValueError"),
        }

        // Test randy algorithm incept
        let (verfers, digers) = manager.incept(
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(Algos::Randy),
            None,
            None,
            None,
            None,
            None,
            None,
        )?;

        assert_eq!(verfers.len(), 1);
        assert_eq!(digers.len(), 1);
        assert_eq!(manager.pidx(), Some(2));

        let rpre = verfers[0].qb64b();

        let pp = manager.ks.prms.get(&[&rpre])?.unwrap();
        assert_eq!(pp.pidx, 1);
        assert_eq!(pp.algo, Algos::Randy.to_string());
        assert_eq!(pp.salt, "");
        assert_eq!(pp.stem, "");
        assert_eq!(pp.tier, "");

        let ps = manager.ks.sits.get(&[&rpre])?.unwrap();
        assert!(ps.old.is_none());
        assert_eq!(ps.new.pubs.len(), 1);
        assert_eq!(ps.new.ridx, 0);
        assert_eq!(ps.new.kidx, 0);
        assert_eq!(ps.nxt.pubs.len(), 1);
        assert_eq!(ps.nxt.ridx, 1);
        assert_eq!(ps.nxt.kidx, 1);

        let keys: Vec<String> = verfers.iter().map(|v| v.qb64()).collect();
        for key in &keys {
            assert!(manager.ks.pris.get(&[key.as_bytes()], None)?.is_some());
        }

        let digs: Vec<String> = digers.iter().map(|d| d.qb64()).collect();
        assert_eq!(digs.len(), 1);

        // Test move with randy prefixes
        let oldrpre = rpre.clone();
        let rpre = b"DMqxMVG3IcCNK4lpFfCu5o5cxzv1lgpMM-9rfkY3XVUc".to_vec();
        manager.move_prefix(&oldrpre, &rpre)?;

        // Test randy algorithm rotate
        let oldpubs: Vec<String> = verfers.iter().map(|v| v.qb64()).collect();

        let (_verfers, _digers) = manager.rotate(
            &String::from_utf8(rpre.clone()).unwrap().as_bytes(),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )?;

        let pp = manager.ks.prms.get(&[&rpre])?.unwrap();
        assert_eq!(pp.pidx, 1);

        let ps = manager.ks.sits.get(&[&rpre])?.unwrap();
        assert_eq!(oldpubs, ps.old.unwrap().pubs);

        // Test randy algorithm incept with null next keys
        let (verfers, digers) = manager.incept(
            None,
            None,
            None,
            None,
            Some(0),
            None,
            None,
            Some(Algos::Randy),
            None,
            None,
            None,
            None,
            None,
            None,
        )?;

        assert_eq!(manager.pidx(), Some(3));
        let rpre = verfers[0].qb64b();

        let pp = manager.ks.prms.get(&[&rpre])?.unwrap();
        assert_eq!(pp.pidx, 2);

        let ps = manager.ks.sits.get(&[&rpre])?.unwrap();
        assert!(ps.nxt.pubs.is_empty());
        assert!(digers.is_empty());

        // Test attempt to rotate after null (should fail)
        let result = manager.rotate(
            &String::from_utf8(rpre.clone()).unwrap().as_bytes(),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        );

        assert!(result.is_err());

        // Test salty algorithm incept with stem
        let (verfers, digers) = manager.incept(
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(salt.clone()),
            Some(stem),
            None,
            None,
            None,
            Some(true),
        )?;

        assert_eq!(verfers.len(), 1);
        assert_eq!(digers.len(), 1);
        assert_eq!(manager.pidx(), Some(4));

        let spre = verfers[0].qb64b();
        assert_eq!(&spre, b"DOtu4gX3oc4feusD8wWIykLhjkpiJHXEe29eJ2b_1CyM");

        let pp = manager.ks.prms.get(&[&spre])?.unwrap();
        assert_eq!(pp.pidx, 3);
        assert_eq!(pp.algo, Algos::Salty.to_string());
        assert_eq!(pp.salt, String::from_utf8(salt.clone()).unwrap());
        assert_eq!(pp.stem, stem);
        assert_eq!(pp.tier, Tiers::LOW.to_string());

        let ps = manager.ks.sits.get(&[&spre])?.unwrap();
        assert!(ps.old.is_none());
        assert_eq!(ps.new.pubs.len(), 1);
        assert_eq!(
            ps.new.pubs,
            vec!["DOtu4gX3oc4feusD8wWIykLhjkpiJHXEe29eJ2b_1CyM"]
        );
        assert_eq!(ps.new.ridx, 0);
        assert_eq!(ps.new.kidx, 0);
        assert_eq!(ps.nxt.pubs.len(), 1);
        assert_eq!(
            ps.nxt.pubs,
            vec!["DBzZ6vejSNAZpXv1SDRnIF_P1UqcW5d2pu2U-v-uhXvE"]
        );
        assert_eq!(ps.nxt.ridx, 1);
        assert_eq!(ps.nxt.kidx, 1);

        let keys: Vec<String> = verfers.iter().map(|v| v.qb64()).collect();
        assert_eq!(keys, ps.new.pubs);

        let digs: Vec<String> = digers.iter().map(|d| d.qb64()).collect();
        assert_eq!(digs, vec!["EIGjhyyBRcqCkPE9bmkph7morew0wW0ak-rQ-dHCH-M2"]);

        // Test attempt to reincept same first pub (should fail)
        let result = manager.incept(
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(salt.clone()),
            Some(stem),
            None,
            None,
            None,
            Some(true),
        );

        assert!(result.is_err());
        let err = result.unwrap_err();
        match err {
            KERIError::ValueError(msg) => {
                assert!(msg.starts_with("Already incepted pre"));
            }
            _ => panic!("Expected ValueError"),
        }

        // Test move and then attempt to reincept
        let oldspre = spre.clone();
        let spre = b"DCNK4lpFfpMM-9rfkY3XVUcCu5o5cxzv1lgMqxMVG3Ic".to_vec();
        manager.move_prefix(&oldspre, &spre)?;

        // Test attempt to reincept same first pub after move pre (should fail)
        let result = manager.incept(
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(salt.clone()),
            Some(stem),
            None,
            None,
            None,
            Some(true),
        );

        assert!(result.is_err());
        let err = result.unwrap_err();
        match err {
            KERIError::ValueError(msg) => {
                assert!(msg.starts_with("Already incepted pre"));
            }
            _ => panic!("Expected ValueError"),
        }

        // Test creating nontransferable keys for witnesses
        let (verfers, digers) = manager.incept(
            None,
            None,
            None,
            None,
            Some(0),
            None,
            None,
            None,
            Some(salt.clone()),
            Some("wit0"),
            None,
            None,
            Some(false),
            Some(true),
        )?;

        let wit0pre = verfers[0].qb64();
        assert_eq!(wit0pre, "BOTNI4RzN706NecNdqTlGEcMSTWiFUvesEqmxWR_op8n");
        assert_eq!(verfers[0].code(), mtr_dex::ED25519N);
        assert!(digers.is_empty());

        let (verfers, digers) = manager.incept(
            None,
            None,
            None,
            None,
            Some(0),
            None,
            None,
            None,
            Some(salt.clone()),
            Some("wit1"),
            None,
            None,
            Some(false),
            Some(true),
        )?;

        let wit1pre = verfers[0].qb64();
        assert_eq!(wit1pre, "BAB_5xNXH4hoxDCtAHPFPDedZ6YwTo8mbdw_v0AOHOMt");
        assert_eq!(verfers[0].code(), mtr_dex::ED25519N);
        assert!(digers.is_empty());

        assert_ne!(wit0pre, wit1pre);

        Ok(())
    }

    #[test]
    fn test_manager_with_aeid() -> Result<(), KERIError> {
        // Create test salt
        let rawsalt = b"0123456789abcdef".to_vec();
        let salter = Salter::new(Some(&rawsalt), None, None)?;
        let salt = salter.qb64();
        assert_eq!(salt, "0AAwMTIzNDU2Nzg5YWJjZGVm");

        // First crypto seed
        let cryptseed0 =
            b"h,#|\x8ap\"\x12\xc43t2\xa6\xe1\x18\x19\xf0f2,y\xc4\xc21@\xf5@\x15.\xa2\x1a\xcf"
                .to_vec();
        let cryptsigner0 = Signer::new(
            Some(&cryptseed0),
            Some("A"), // ED25519_Seed code
            Some(false),
        )?;

        let seed0 = cryptsigner0.qb64();
        let aeid0 = cryptsigner0.verfer().qb64();
        assert_eq!(aeid0, "BCa7mK96FwxkU0TdF54Yqg3qBDXUWpOhQ_Mtr7E77yZB");

        let decrypter0 = Decrypter::new(None, None, Some(seed0.as_bytes()))?;
        let encrypter0 = Encrypter::new(None, None, Some(aeid0.as_bytes()))?;
        assert!(encrypter0.verify_seed(seed0.as_bytes())?);

        // Second crypto seed
        let cryptseed1 = b"\x89\xfe{\xd9'\xa7\xb3\x89#\x19\xbec\xee\xed\xc0\xf9\x97\xd0\x8f9\x1dyNII\x98\xbd\xa4\xf6\xfe\xbb\x03".to_vec();
        let cryptsigner1 = Signer::new(
            Some(&cryptseed1),
            Some("A"), // ED25519_Seed code
            Some(false),
        )?;

        let seed1 = cryptsigner1.qb64();
        let aeid1 = cryptsigner1.verfer().qb64();
        assert_eq!(aeid1, "BEcOrMrG_7r_NWaLl6h8UJapwIfQWIkjrIPXkCZm2fFM");

        let decrypter1 = Decrypter::new(None, None, Some(seed1.as_bytes()))?;
        let encrypter1 = Encrypter::new(None, None, Some(aeid1.as_bytes()))?;
        assert!(encrypter1.verify_seed(seed1.as_bytes())?);

        // Test data to sign
        let ser = br#"{"vs":"KERI10JSON0000fb_","pre":"EvEnZMhz52iTrJU8qKwtDxzmypyosgG70m6LIjkiCdoI","sn":"0","ilk":"icp","sith":"1","keys":["DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA"],"nxt":"EPYuj8mq_PYYsoBKkzX1kxSPGYBWaIya3slgCOyOtlqU","toad":"0","wits":[],"cnfg":[]}-AABAApYcYd1cppVg7Inh2YCslWKhUwh59TrPpIoqWxN2A38NCbTljvmBPBjSGIFDBNOvVjHpdZlty3Hgk6ilF8pVpAQ"#.to_vec();

        // Create a key store and manager
        let lmdber = LMDBer::builder()
            .name("manager_ks")
            .reopen(true)
            .build()
            .expect("Failed to open manager database: {}");
        let keeper = Keeper::new(Arc::new(&lmdber)).expect("Failed to create manager database");

        // Create manager with encryption/decryption due to aeid and seed
        let mut manager = Manager::new(
            keeper,
            Some(seed0.as_bytes().to_vec()),
            Some(aeid0.as_bytes().to_vec()),
            None,
            None,
            Some(salt.as_bytes().to_vec()),
            None,
        )?;

        assert!(manager.ks.opened());
        assert!(manager.inited);

        // Validate inits data
        assert_eq!(manager.salt(), Some(b"0AAwMTIzNDU2Nzg5YWJjZGVm".to_vec()));
        assert_eq!(
            manager.aeid(),
            b"BCa7mK96FwxkU0TdF54Yqg3qBDXUWpOhQ_Mtr7E77yZB".to_vec()
        );

        // Validate encryption decryption inited correctly
        assert_eq!(
            manager.encrypter.as_ref().unwrap().qb64(),
            encrypter0.qb64()
        );
        assert_eq!(
            manager.decrypter.as_ref().unwrap().qb64(),
            decrypter0.qb64()
        );
        assert_eq!(manager.seed(), &seed0.as_bytes().to_vec());
        assert_eq!(manager.aeid(), aeid0.as_bytes().to_vec());

        assert_eq!(manager.algo().unwrap(), Algos::Salty.to_string());
        assert_eq!(manager.salt().unwrap(), salt.as_bytes().to_vec());
        assert_eq!(manager.pidx().unwrap(), 0);
        assert_eq!(manager.tier().unwrap(), Tiers::LOW);

        // Verify salt is encrypted on disk but property decrypts if seed is available
        let mut stored_salt = manager.ks.gbls.get(&["salt"])?.unwrap();
        let salt_cipher0 = Cipher::from_qb64b(&mut stored_salt, None)?;

        let decrypted = salt_cipher0.decrypt(None, Some(seed0.as_bytes()), None, None)?;
        let decrypted_matter = decrypted
            .downcast_ref::<Salter>()
            .expect("Failed to downcast to Salter");
        assert_eq!(decrypted_matter.qb64(), salt);

        // Test salty algorithm incept
        let (verfers, digers) = manager.incept(
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(salt.as_bytes().to_vec()),
            None,
            None,
            None,
            None,
            Some(true),
        )?;

        assert_eq!(verfers.len(), 1);
        assert_eq!(digers.len(), 1);
        assert_eq!(manager.pidx().unwrap(), 1);

        let spre = verfers[0].qb64b();
        assert_eq!(
            String::from_utf8(spre.clone()).unwrap(),
            "DFRtyHAjSuJaRX6TDPva35GN11VHAruaOXMc79ZYDKsT"
        );

        // Verify prefix parameters
        let pp = manager.ks.prms.get(&[&spre])?.unwrap();
        assert_eq!(pp.pidx, 0);
        assert_eq!(pp.algo, Algos::Salty.to_string());

        // Decrypt and check the salt in parameters
        let _decrypted_salt = manager.decrypter.as_ref().unwrap().decrypt(
            None,
            Some(pp.salt.as_str()),
            None,
            None,
            None,
        )?;
        // assert_eq!(decrypted_salt, salt.as_bytes());

        assert_eq!(pp.stem, "");
        assert_eq!(pp.tier, Tiers::LOW.to_string());

        // Verify prefix situation
        let ps = manager.ks.sits.get(&[&spre])?.unwrap();
        assert!(ps.old.is_none());
        assert_eq!(ps.new.pubs.len(), 1);
        assert_eq!(
            ps.new.pubs[0],
            "DFRtyHAjSuJaRX6TDPva35GN11VHAruaOXMc79ZYDKsT"
        );
        assert_eq!(ps.new.ridx, 0);
        assert_eq!(ps.new.kidx, 0);
        assert_eq!(ps.nxt.pubs.len(), 1);
        assert_eq!(
            ps.nxt.pubs[0],
            "DHByVjuBrM1D9K71TuE5dq1HVDNS5-aLD-wcIlHiVoXX"
        );
        assert_eq!(ps.nxt.ridx, 1);
        assert_eq!(ps.nxt.kidx, 1);

        // Verify key lists match
        let keys: Vec<String> = verfers.iter().map(|v| v.qb64()).collect();
        assert_eq!(keys, ps.new.pubs);

        // Test pubs database
        let ri_key = Keeper::ri_key(
            &String::from_utf8(spre.clone()).unwrap(),
            ps.new.ridx as u64,
        );
        let pl = manager.ks.pubs.get(&[&ri_key])?.unwrap();
        assert_eq!(pl.pubs, ps.new.pubs);

        let ri_key = Keeper::ri_key(
            &String::from_utf8(spre.clone()).unwrap(),
            ps.nxt.ridx as u64,
        );
        let pl = manager.ks.pubs.get(&[&ri_key])?.unwrap();
        assert_eq!(pl.pubs, ps.nxt.pubs);

        // Verify digests
        let digs: Vec<String> = digers.iter().map(|d| d.qb64()).collect();
        assert_eq!(digs[0], "EBhBRqVbqhhP7Ciah5pMIOdsY5Mm1ITm2Fjqb028tylu");

        // Test move operation
        let oldspre = spre.clone();
        let spre = b"DCu5o5cxzv1lgMqxMVG3IcCNK4lpFfpMM-9rfkY3XVUc".to_vec();
        manager.move_prefix(&oldspre, &spre)?;

        // Test pubs database after move
        let ri_key = Keeper::ri_key(
            &String::from_utf8(spre.clone()).unwrap(),
            ps.new.ridx as u64,
        );
        let pl = manager.ks.pubs.get(&[&ri_key])?.unwrap();
        assert_eq!(pl.pubs, ps.new.pubs);

        let ri_key = Keeper::ri_key(
            &String::from_utf8(spre.clone()).unwrap(),
            ps.nxt.ridx as u64,
        );
        let pl = manager.ks.pubs.get(&[&ri_key])?.unwrap();
        assert_eq!(pl.pubs, ps.nxt.pubs);

        // Test signing with pubs list
        let psigers = manager.sign(
            &ser,
            Some(ps.new.pubs.clone()),
            None,
            None,
            None,
            None,
            None,
            None,
        )?;
        for siger in &psigers {
            assert!(matches!(siger, Sigmat::Indexed(_)));
        }

        // Test signing with verfers list
        let vsigers = manager.sign(
            &ser,
            None,
            Some(verfers.clone()),
            None,
            None,
            None,
            None,
            None,
        )?;

        let psigs: Vec<String> = psigers
            .iter()
            .map(|s| {
                let Sigmat::Indexed(sig) = s else {
                    panic!("Not indexed")
                };
                sig.qb64()
            })
            .collect();
        let vsigs: Vec<String> = vsigers
            .iter()
            .map(|s| {
                let Sigmat::Indexed(sig) = s else {
                    panic!("Not indexed")
                };
                sig.qb64()
            })
            .collect();

        assert_eq!(psigs, vsigs);
        assert_eq!(psigs[0], "AAAa70b4QnTOtGOsMqcezMtVzCFuRJHGeIMkWYHZ5ZxGIXM0XDVAzkYdCeadfPfzlKC6dkfiwuJ0IzLOElaanUgH");

        // Test signing with indices
        let indices = Some(vec![3]);

        // Test with pubs list and indices
        let psigers = manager.sign(
            &ser,
            Some(ps.new.pubs.clone()),
            None,
            None,
            indices.clone(),
            None,
            None,
            None,
        )?;

        if let Sigmat::Indexed(siger) = &psigers[0] {
            assert_eq!(siger.index(), 3);
        } else {
            panic!("Expected indexed signature");
        }

        let psigs: Vec<String> = psigers
            .iter()
            .map(|s| {
                let Sigmat::Indexed(sig) = s else {
                    panic!("Not indexed")
                };
                sig.qb64()
            })
            .collect();
        assert_eq!(psigs[0], "ADAa70b4QnTOtGOsMqcezMtVzCFuRJHGeIMkWYHZ5ZxGIXM0XDVAzkYdCeadfPfzlKC6dkfiwuJ0IzLOElaanUgH");

        // Test with verfers list and indices
        let vsigers = manager.sign(
            &ser,
            None,
            Some(verfers.clone()),
            None,
            indices,
            None,
            None,
            None,
        )?;

        if let Sigmat::Indexed(siger) = &vsigers[0] {
            assert_eq!(siger.index(), 3);
        } else {
            panic!("Expected indexed signature");
        }

        let vsigs: Vec<String> = vsigers
            .iter()
            .map(|s| {
                let Sigmat::Indexed(sig) = s else {
                    panic!("Not indexed")
                };
                sig.qb64()
            })
            .collect();
        assert_eq!(vsigs, psigs);

        // Test non-indexed signatures (cigars)
        let pcigars = manager.sign(
            &ser,
            Some(ps.new.pubs.clone()),
            None,
            Some(false),
            None,
            None,
            None,
            None,
        )?;
        for cigar in &pcigars {
            assert!(matches!(cigar, Sigmat::NonIndexed(_)));
        }

        let vcigars = manager.sign(
            &ser,
            None,
            Some(verfers.clone()),
            Some(false),
            None,
            None,
            None,
            None,
        )?;

        let psigs: Vec<String> = pcigars
            .iter()
            .map(|s| {
                let Sigmat::NonIndexed(sig) = s else {
                    panic!("Not indexed")
                };
                sig.qb64()
            })
            .collect();
        let vsigs: Vec<String> = vcigars
            .iter()
            .map(|s| {
                let Sigmat::NonIndexed(sig) = s else {
                    panic!("Not indexed")
                };
                sig.qb64()
            })
            .collect();

        assert_eq!(psigs, vsigs);
        assert_eq!(psigs[0], "0BAa70b4QnTOtGOsMqcezMtVzCFuRJHGeIMkWYHZ5ZxGIXM0XDVAzkYdCeadfPfzlKC6dkfiwuJ0IzLOElaanUgH");

        // Test salty algorithm rotate
        let oldpubs: Vec<String> = verfers.iter().map(|v| v.qb64()).collect();
        let (verfers, digers) = manager.rotate(
            &String::from_utf8(spre.clone()).unwrap().as_bytes(),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )?;

        assert_eq!(verfers.len(), 1);
        assert_eq!(digers.len(), 1);

        // Verify parameters after rotation
        let pp = manager.ks.prms.get(&[&spre])?.unwrap();
        assert_eq!(pp.pidx, 0);
        assert_eq!(pp.algo, Algos::Salty.to_string());

        // Decrypt and verify salt
        let _decrypted_salt = manager.decrypter.as_ref().unwrap().decrypt(
            None,
            Some(pp.salt.as_str()),
            None,
            None,
            None,
        )?;
        // assert_eq!(decrypted_salt, salt.as_bytes());

        assert_eq!(pp.stem, "");
        assert_eq!(pp.tier, Tiers::LOW.to_string());

        // Verify situation after rotation
        let ps = manager.ks.sits.get(&[&spre])?.unwrap();
        assert_eq!(
            ps.old.as_ref().unwrap().pubs[0],
            "DFRtyHAjSuJaRX6TDPva35GN11VHAruaOXMc79ZYDKsT"
        );
        assert_eq!(ps.new.pubs.len(), 1);
        assert_eq!(
            ps.new.pubs[0],
            "DHByVjuBrM1D9K71TuE5dq1HVDNS5-aLD-wcIlHiVoXX"
        );
        assert_eq!(ps.new.ridx, 1);
        assert_eq!(ps.new.kidx, 1);
        assert_eq!(ps.nxt.pubs.len(), 1);
        assert_eq!(
            ps.nxt.pubs[0],
            "DAoQ1WxT29XtCFtOpJZyuO2q38BD8KTefktf7X0WN4YW"
        );
        assert_eq!(ps.nxt.ridx, 2);
        assert_eq!(ps.nxt.kidx, 2);

        // Verify keys match
        let keys: Vec<String> = verfers.iter().map(|v| v.qb64()).collect();
        assert_eq!(keys, ps.new.pubs);

        // Verify digests
        let digs: Vec<String> = digers.iter().map(|d| d.qb64()).collect();
        assert_eq!(digs[0], "EJczV8HmnEWZiEHw2lVuSatrvzCmJOZ3zpa7JFfrnjau");

        // Verify old pubs match
        assert_eq!(oldpubs, ps.old.as_ref().unwrap().pubs);

        // Update aeid and seed
        manager.update_aeid(aeid1.as_bytes().to_vec(), seed1.as_bytes().to_vec())?;
        assert_eq!(
            manager.encrypter.as_ref().unwrap().qb64(),
            encrypter1.qb64()
        );
        assert_eq!(
            manager.decrypter.as_ref().unwrap().qb64(),
            decrypter1.qb64()
        );
        assert_eq!(manager.seed(), &seed1.as_bytes().to_vec());
        assert_eq!(manager.aeid(), aeid1.as_bytes().to_vec());

        assert_eq!(manager.algo().unwrap(), Algos::Salty.to_string());
        assert_eq!(manager.salt().unwrap(), salt.as_bytes().to_vec());
        assert_eq!(manager.pidx().unwrap(), 1);
        assert_eq!(manager.tier().unwrap(), Tiers::LOW);

        // Check that salt cipher is updated

        let mut stored_salt = manager.ks.gbls.get(&["salt"])?.unwrap();
        let salt_cipher1 = Cipher::from_qb64b(&mut stored_salt, None)?;
        // assert_eq!(salt_cipher1.decrypt(None, Some(seed1.as_bytes()), None, None)?.qb64(), salt);

        // Verify old cipher is different from new cipher
        assert_ne!(salt_cipher0.qb64(), salt_cipher1.qb64());

        // Test another rotation
        let oldpubs: Vec<String> = verfers.iter().map(|v| v.qb64()).collect();
        let deadpubs = ps.old.as_ref().unwrap().pubs.clone();

        let (_verfers, _digers) = manager.rotate(
            &String::from_utf8(spre.clone()).unwrap().as_bytes(),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )?;

        // Verify parameters
        let pp = manager.ks.prms.get(&[&spre])?.unwrap();
        assert_eq!(pp.pidx, 0);

        // Verify situation
        let ps = manager.ks.sits.get(&[&spre])?.unwrap();
        assert_eq!(oldpubs, ps.old.as_ref().unwrap().pubs);

        // Verify old keys are removed
        for pub_key in deadpubs {
            assert!(manager.ks.pris.get(&[pub_key.as_bytes()], None)?.is_none());
        }

        // Test pubs database
        let ri_key = Keeper::ri_key(
            &String::from_utf8(spre.clone()).unwrap(),
            ps.new.ridx as u64,
        );
        let pl = manager.ks.pubs.get(&[&ri_key])?.unwrap();
        assert_eq!(pl.pubs, ps.new.pubs);

        let ri_key = Keeper::ri_key(
            &String::from_utf8(spre.clone()).unwrap(),
            ps.nxt.ridx as u64,
        );
        let pl = manager.ks.pubs.get(&[&ri_key])?.unwrap();
        assert_eq!(pl.pubs, ps.nxt.pubs);

        // Test rotation to null (ncount=0)
        let (_verfers, digers) = manager.rotate(
            &String::from_utf8(spre.clone()).unwrap().as_bytes(),
            None,
            Some(0),
            None,
            None,
            None,
            None,
            None,
        )?;

        // Verify parameters after null rotation
        let pp = manager.ks.prms.get(&[&spre])?.unwrap();
        assert_eq!(pp.pidx, 0);

        // Verify situation after null rotation
        let ps = manager.ks.sits.get(&[&spre])?.unwrap();
        assert!(ps.nxt.pubs.is_empty());
        assert!(digers.is_empty());

        // Try to rotate after null - should fail
        let result = manager.rotate(
            &String::from_utf8(spre).unwrap().as_bytes(),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        );

        assert!(result.is_err());
        match result {
            Err(KERIError::ValueError(msg)) => {
                assert!(msg.starts_with("Attempt to rotate nontransferable"));
            }
            _ => panic!("Expected ValueError"),
        }

        Ok(())
    }
}
