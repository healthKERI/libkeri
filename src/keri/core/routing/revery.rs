use super::router::Router;
use crate::cesr::dater::Dater;
use crate::cesr::indexing::siger::Siger;
use crate::cesr::prefixer::Prefixer;
use crate::cesr::saider::Saider;
use crate::cesr::seqner::Seqner;
use crate::cesr::verfer::Verfer;
use crate::cesr::Matter;
use crate::keri::core::eventing;
use crate::keri::core::serdering::{Rawifiable, Serder, SerderKERI};
use crate::keri::db::basing::Baser;
use crate::keri::db::dbing::keys::{dg_key, sn_key};
use crate::keri::KERIError;
use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::{debug, info, trace, warn};

pub const TIMEOUT_RPE: u64 = 3600;

/// Reply message event processor
pub struct Revery<'db> {
    /// Timeout for reply message escrows (in seconds)

    /// Database instance
    pub db: Arc<&'db Baser<'db>>,

    /// Router for dispatching reply messages
    pub rtr: Router,

    /// Cues for processing
    pub cues: VecDeque<ReplyMessageCue>,

    /// Promiscuous mode flag
    pub lax: bool,

    /// Local vs nonlocal restrictions
    pub local: bool,
}

/// Cue for reply message processing
#[derive(Debug, Clone)]
pub struct ReplyMessageCue {
    pub kind: String,
    pub data: std::collections::HashMap<String, serde_json::Value>,
}

impl<'db> Revery<'db> {
    /// Initialize new Revery instance
    pub fn new(
        db: Arc<&'db Baser<'db>>,
        rtr: Option<Router>,
        cues: Option<VecDeque<ReplyMessageCue>>,
        lax: Option<bool>,
        local: Option<bool>,
    ) -> Self {
        Self {
            db,
            rtr: rtr.unwrap_or_else(|| Router::new(None)),
            cues: cues.unwrap_or_else(VecDeque::new),
            lax: lax.unwrap_or(true),
            local: local.unwrap_or(false),
        }
    }

    /// Get prefixes from database
    pub fn prefixes(&self) -> &indexmap::IndexSet<String> {
        &self.db.prefixes
    }

    /// Process one reply message with attached signatures
    ///
    /// Process logic is route dependent and dispatched by route.
    ///
    /// # Parameters
    /// * `serder` - Instance of reply message
    /// * `cigars` - Non-transferable signature instances
    /// * `tsgs` - Transferable signature groups
    ///
    /// BADA (Best Available Data Acceptance) model for each reply message.
    /// Latest-Seen-Signed Pairwise comparison of new update reply compared to
    /// old already accepted reply from same source for same route (same data).
    pub fn process_reply(
        &self,
        serder: SerderKERI,
        cigars: Option<Vec<Siger>>,
        tsgs: Option<Vec<(Prefixer, Seqner, Saider, Vec<Siger>)>>,
    ) -> Result<(), KERIError> {
        let ked = serder.ked();

        // Verify SAID of reply
        let saider = Saider::from_qb64(
            ked.get("d")
                .and_then(|v| v.as_str())
                .ok_or_else(|| KERIError::ValueError("Missing 'd' field in reply".to_string()))?,
        )?;

        // Use the correct verify method signature
        if !saider.verify(&ked, true, false, None, "d", None) {
            return Err(KERIError::ValidationError(format!(
                "Invalid said = {} for reply msg",
                saider.qb64()
            )));
        }

        // Dispatch to appropriate route handler
        self.rtr
            .dispatch(&serder, &saider, cigars.as_deref(), tsgs.as_deref())?;

        Ok(())
    }

    /// Apply Best Available Data Acceptance policy to reply and signatures
    ///
    /// # Returns
    /// * `true` if successfully accepted, `false` otherwise
    ///
    /// # Parameters
    /// * `serder` - Instance of reply msg (SAD)
    /// * `saider` - Instance from said in serder (SAD)
    /// * `osaider` - Instance of saider for previous reply if any
    /// * `route` - Reply route
    /// * `aid` - Identifier prefix qb64 of authorizing attributable ID
    /// * `cigars` - Non-transferable signature instances
    /// * `tsgs` - Transferable signature groups
    #[allow(clippy::too_many_arguments)]
    pub fn accept_reply(
        &mut self,
        serder: &SerderKERI,
        saider: &Saider,
        route: &str,
        aid: &str,
        osaider: Option<&Saider>,
        cigars: Option<&[Siger]>,
        tsgs: Option<&[(Prefixer, Seqner, Saider, Vec<Siger>)]>, // Third element is Saider
    ) -> Result<bool, KERIError> {
        let mut accepted = false;
        let cigars = cigars.unwrap_or(&[]);
        let tsgs = tsgs.unwrap_or(&[]);

        // Get date-time for BADA comparison
        let dater = Dater::from_dts(
            serder
                .ked()
                .get("dt")
                .and_then(|v| v.as_str())
                .ok_or_else(|| KERIError::ValueError("Missing 'dt' field in reply".to_string()))?,
        )?;

        let odater = if let Some(osaider) = osaider {
            self.db.sdts.get(&[&osaider.qb64()])?
        } else {
            None
        };

        // Process non-transferable signatures (cigars)
        for cigar in cigars {
            let verfer = match cigar.verfer() {
                Some(v) => v,
                None => {
                    info!(
                        "Revery: skipped cigar with no verfer on reply said = {}",
                        serder.said().unwrap_or_default()
                    );
                    continue;
                }
            };

            if verfer.is_transferable() {
                info!(
                    "Revery: skipped invalid transferable verfer on reply said = {}",
                    serder.said().unwrap_or_default()
                );
                continue;
            }

            if !self.lax && self.prefixes().contains(&verfer.qb64()) {
                if !self.local {
                    info!(
                "Revery: skipped own attachment for AID {} on non-local reply at route = {}",
                aid,
                serder.ked().get("r").and_then(|v| v.as_str()).unwrap_or("unknown")
            );
                    debug!("Reply Body=\n{}\n", serder.pretty(None));
                    continue;
                }
            }

            if aid != verfer.qb64() {
                info!(
                    "Revery: skipped cigar not from aid={} on reply at route {}",
                    aid,
                    serder
                        .ked()
                        .get("r")
                        .and_then(|v| v.as_str())
                        .unwrap_or("unknown")
                );
                debug!("Reply Body=\n{}\n", serder.pretty(None));
                continue;
            }

            // Check if this is later than previous version
            if let Some(ref odater) = odater {
                if dater.dt()? <= odater.dt()? {
                    trace!(
                        "Revery: skipped stale update from {} of reply at route = {}",
                        aid,
                        serder
                            .ked()
                            .get("r")
                            .and_then(|v| v.as_str())
                            .unwrap_or("unknown")
                    );
                    trace!("Reply Body=\n{}\n", serder.pretty(None));
                    continue;
                }
            }

            // Verify signature
            if !verfer.verify(&cigar.raw(), &serder.raw())? {
                info!(
                    "Revery: skipped non-verifying cigar from {} on reply at route = {}",
                    verfer.qb64(),
                    serder
                        .ked()
                        .get("r")
                        .and_then(|v| v.as_str())
                        .unwrap_or("unknown")
                );
                debug!("Reply Body=\n{}\n", serder.pretty(None));
                continue;
            }

            // All constraints satisfied, update the reply
            self.update_reply(serder, saider, &dater, Some(cigar), None, None, None, None)?;
            if let Some(osaider) = osaider {
                self.remove_reply(osaider)?;
            }
            accepted = true;
            break; // First valid cigar is sufficient
        }

        // Process transferable signatures (tsgs)
        for (prefixer, seqner, ssaider, sigers) in tsgs {
            if !self.lax && self.prefixes().contains(&prefixer.qb64()) {
                if !self.local {
                    debug!(
                        "Revery: skipped own attachment on nonlocal reply said={}",
                        serder.said().unwrap_or_default()
                    );
                    debug!("event=\n{}\n", serder.pretty(None));
                    continue;
                }
            }

            let spre = &prefixer.qb64();
            if aid != spre {
                info!(
                    "Revery: skipped signature not from aid={} on reply said={}",
                    aid,
                    serder.said().unwrap_or_default()
                );
                debug!("event=\n{}\n", serder.pretty(None));
                continue;
            }

            // Check if this is later than previous version for transferable signatures
            if let Some(osaider) = osaider {
                let otsgs = self.db.fetch_tsgs(osaider.clone(), None)?;
                if !otsgs.is_empty() {
                    let (_, osqr, _, _) = &otsgs[0];

                    if seqner.sn() < osqr.sn() {
                        info!(
                            "Revery: skipped stale key state sig from {} sn={}<{} on reply said={}",
                            aid,
                            seqner.sn(),
                            osqr.sn(),
                            serder.said().unwrap_or_default()
                        );
                        debug!("event=\n{}\n", serder.pretty(None));
                        continue;
                    }

                    if seqner.sn() == osqr.sn() {
                        if let Some(ref odater) = odater {
                            if dater.dt()? <= odater.dt()? {
                                info!(
                                    "Revery: skipped stale key state sig datetime from {} on reply said={}",
                                    aid, serder.said().unwrap_or_default()
                                );
                                debug!("event=\n{}\n", serder.pretty(None));
                                continue;
                            }
                        }
                    }
                }
            }

            // Retrieve last event at sequence number for signer
            let sdig = self
                .db
                .kels
                .get_last::<_, Vec<u8>>(&[&sn_key(spre, seqner.sn())])?;

            let sdig = match sdig {
                Some(dig_bytes) => String::from_utf8(dig_bytes)
                    .map_err(|_| KERIError::ValueError("Invalid UTF-8 in digest".to_string()))?,
                None => {
                    // Escrow if signer's establishment event not yet available
                    info!(
                        "Revery: escrowing without key state for signer on reply said={}",
                        serder.said().unwrap_or_default()
                    );
                    self.escrow_reply(
                        serder, saider, &dater, route, prefixer, seqner, ssaider, sigers,
                    )?;

                    // Add cue to request key state
                    self.cues.push_back(ReplyMessageCue {
                        kind: "query".to_string(),
                        data: {
                            let mut data = std::collections::HashMap::new();
                            data.insert("pre".to_string(), serde_json::Value::String(spre.clone()));
                            data
                        },
                    });
                    continue;
                }
            };

            // Retrieve the establishment event itself
            let sraw = self
                .db
                .evts
                .get::<_, Vec<u8>>(&[&dg_key(spre, &sdig)])?
                .ok_or_else(|| {
                    KERIError::ValueError(format!("Event not found for dig={}", sdig))
                })?;

            let sserder = SerderKERI::from_raw(&sraw, None)?;

            if sserder.said().unwrap_or_default() != ssaider.qb64() {
                return Err(KERIError::ValidationError(format!(
                    "Bad trans indexed sig group at sn = {} for reply",
                    seqner.sn()
                )));
            }

            // Verify signatures
            let sverfers = sserder.verfers().ok_or_else(|| {
                KERIError::ValidationError(format!(
                    "Invalid reply from signer={}, no keys at signer's est. event sn={}",
                    spre,
                    seqner.sn()
                ))
            })?;

            // Fetch any escrowed signatures and combine with current ones
            let mut all_sigers = sigers.clone();
            let quad_keys = (
                saider.qb64(),
                prefixer.qb64(),
                format!("{:032x}", seqner.sn()),
                ssaider.qb64(),
            );

            let esigers_result =
                self.db
                    .ssgs
                    .get(&[&quad_keys.0, &quad_keys.1, &quad_keys.2, &quad_keys.3])?;

            if !esigers_result.is_empty() {
                for matter_vec in esigers_result {
                    for matter in matter_vec {
                        if let Some(siger) = matter.as_any().downcast_ref::<Siger>() {
                            all_sigers.push(siger.clone());
                        }
                    }
                }
            }

            // Validate signatures against thresholds
            let tholder = sserder.tholder().ok_or_else(|| {
                KERIError::ValidationError(format!(
                    "No tholder available for establishment event at sn={}",
                    seqner.sn()
                ))
            })?;

            let (valid_sigers, valid) =
                eventing::validate_sigs(serder, all_sigers, &sverfers, &tholder)?;

            if valid {
                // All constraints satisfied, update the reply
                self.update_reply(
                    serder,
                    saider,
                    &dater,
                    None,
                    Some(prefixer),
                    Some(seqner),
                    Some(ssaider),
                    Some(&valid_sigers),
                )?;

                if let Some(osaider) = osaider {
                    self.remove_reply(osaider)?;
                }

                // Remove stale signatures
                let tsgs_to_trim = self.db.fetch_tsgs(saider.clone(), Some(&seqner.snh()))?;
                for (prr, snr, dgr, _) in tsgs_to_trim {
                    if snr.sn() < seqner.sn()
                        || (snr.sn() == seqner.sn() && dgr.qb64() != ssaider.qb64())
                    {
                        let trim_keys = (
                            prr.qb64(),
                            format!("{:032x}", snr.sn()),
                            dgr.qb64(),
                            String::new(),
                        );
                        self.db.ssgs.trim(
                            &[&trim_keys.0, &trim_keys.1, &trim_keys.2, &trim_keys.3],
                            true,
                        )?;
                    }
                }

                accepted = true;
            } else {
                // Not meeting threshold, escrow
                self.escrow_reply(
                    serder, saider, &dater, route, prefixer, seqner, ssaider, sigers,
                )?;
            }
        }

        Ok(accepted)
    }

    /// Update Reply SAD in database
    #[allow(clippy::too_many_arguments)]
    pub fn update_reply(
        &self,
        serder: &SerderKERI,
        saider: &Saider,
        dater: &Dater,
        cigar: Option<&Siger>,
        prefixer: Option<&Prefixer>,
        seqner: Option<&Seqner>,
        diger: Option<&Saider>, // This is actually a Saider in the Python code
        sigers: Option<&[Siger]>,
    ) -> Result<(), KERIError> {
        let keys = [saider.qb64()];

        // Store datetime, reply, and signatures
        self.db.sdts.put(&keys, dater)?;
        self.db.rpys.put(&keys, serder)?;

        if let Some(cigar) = cigar {
            if let Some(verfer) = cigar.verfer() {
                self.db.scgs.put(&keys, &[&verfer, cigar])?;
            }
        }

        if let Some(sigers) = sigers {
            if let (Some(prefixer), Some(seqner), Some(diger)) = (prefixer, seqner, diger) {
                let quad_keys = (
                    saider.qb64(),
                    prefixer.qb64(),
                    format!("{:032x}", seqner.sn()),
                    diger.qb64(), // diger is actually a Saider
                );
                let sigers_as_matter: Vec<&dyn Matter> =
                    sigers.iter().map(|s| s as &dyn Matter).collect();
                self.db.ssgs.put(
                    &[&quad_keys.0, &quad_keys.1, &quad_keys.2, &quad_keys.3],
                    &sigers_as_matter,
                )?;
            }
        }

        Ok(())
    }

    /// Remove Reply SAD artifacts given by saider
    pub fn remove_reply(&self, saider: &Saider) -> Result<(), KERIError> {
        let keys = [saider.qb64()];

        // Remove all related data
        let saider_b64 = saider.qb64();
        self.db.ssgs.trim(&[saider_b64.as_ref(), ""], true)?; // Remove whole branch
        self.db.scgs.rem(&keys, None)?;
        self.db.rpys.rem(&keys)?;
        self.db.sdts.rem(&keys)?;

        Ok(())
    }

    /// Escrow reply by route
    #[allow(clippy::too_many_arguments)]
    pub fn escrow_reply(
        &self,
        serder: &SerderKERI,
        saider: &Saider,
        dater: &Dater,
        route: &str,
        prefixer: &Prefixer,
        seqner: &Seqner,
        ssaider: &Saider,
        sigers: &[Siger],
    ) -> Result<(), KERIError> {
        if sigers.is_empty() {
            return Ok(()); // Nothing to escrow
        }

        let keys = [saider.qb64()];

        // Store escrow data
        self.db.sdts.put(&keys, dater)?;
        self.db.rpys.put(&keys, serder)?;

        let quad_keys = (
            saider.qb64(),
            prefixer.qb64(),
            format!("{:032x}", seqner.sn()),
            ssaider.qb64(),
        );
        let sigers_as_matter: Vec<&dyn Matter> = sigers.iter().map(|s| s as &dyn Matter).collect();
        self.db.ssgs.put(
            &[&quad_keys.0, &quad_keys.1, &quad_keys.2, &quad_keys.3],
            &sigers_as_matter,
        )?;

        // Add to reply escrow
        self.db.rpes.put(&[route], &[saider])?;

        Ok(())
    }

    /// Process escrows for reply messages
    ///
    /// Escrows are keyed by reply route and val is reply said
    pub fn process_escrow_reply(&mut self) -> Result<(), KERIError> {
        let mut items_to_process = Vec::new();

        // Collect items to process to avoid borrowing issues
        let iter_results = self.db.rpes.get_item_iter(&[""], true)?;
        for (keys, saider) in iter_results {
            if let Some(route) = keys.get(0) {
                items_to_process.push((route.clone(), saider.clone()));
            }
        }

        for (route, saider) in items_to_process {
            // Convert Vec<u8> to String
            let route_str = match String::from_utf8(route) {
                Ok(s) => s,
                Err(e) => {
                    warn!("Invalid UTF-8 in route: {}", e);
                    continue;
                }
            };

            match self.process_single_escrow(&route_str, &saider) {
                Ok(success) => {
                    if success {
                        // Remove from escrow on success
                        self.db.rpes.rem(&[&route_str.as_bytes()], None)?;
                        info!("Revery unescrow succeeded for reply said={}", saider.qb64());
                    }
                }
                Err(e) => {
                    // Remove failed escrow
                    self.db.rpes.rem(&[&route_str.as_bytes()], None)?;
                    self.remove_reply(&saider)?;
                    debug!("Revery unescrowed due to error: {}", e);
                }
            }
        }

        Ok(())
    }

    /// Process a single escrowed reply
    fn process_single_escrow(&self, route: &str, saider: &Saider) -> Result<bool, KERIError> {
        // Convert Diger-based tsgs to Saider-based tsgs for compatibility
        let tsgs_raw = self.db.fetch_tsgs(saider.clone(), None)?;

        let tsgs: Vec<(Prefixer, Seqner, Saider, Vec<Siger>)> = tsgs_raw
            .into_iter()
            .map(|(prefixer, seqner, diger, sigers)| {
                // Convert Diger to Saider - they should have the same qb64 representation
                let saider = Saider::from_qb64(&diger.qb64()).unwrap_or_else(|_| {
                    // This should not fail since Diger and Saider use same encoding
                    panic!("Failed to convert Diger to Saider: {}", diger.qb64())
                });
                (prefixer, seqner, saider, sigers)
            })
            .collect();

        let keys = [saider.qb64()];

        let dater = self
            .db
            .sdts
            .get::<_>(&keys)?
            .ok_or_else(|| KERIError::ValueError("Missing escrow datetime".to_string()))?;

        let serder = self
            .db
            .rpys
            .get::<_>(&keys)?
            .ok_or_else(|| KERIError::ValueError("Missing escrow serder".to_string()))?;

        // Check if we have the required artifacts
        if tsgs.is_empty() {
            return Err(KERIError::ValueError(format!(
                "Missing escrow artifacts at said={} for route={}",
                saider.qb64(),
                route
            )));
        }

        // Check for stale escrow
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| KERIError::ValueError(format!("System time error: {}", e)))?;

        let escrow_datetime = dater
            .dt()
            .map_err(|e| KERIError::ValueError(format!("Invalid datetime format: {:?}", e)))?;

        let escrow_age =
            now.saturating_sub(Duration::from_secs(escrow_datetime.timestamp() as u64));

        if escrow_age > Duration::from_secs(TIMEOUT_RPE) {
            info!(
                "Revery unescrow error: Stale reply escrow at route = {}",
                route
            );
            return Err(KERIError::ValidationError(format!(
                "Stale reply escrow at route = {}",
                route
            )));
        }

        // Try to process the escrowed reply
        self.process_reply(serder, None, Some(tsgs))?;

        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keri::db::dbing::LMDBer;

    #[test]
    fn test_revery_new() -> Result<(), KERIError> {
        let lmdber = &LMDBer::builder()
            .temp(true)
            .name("test_revery")
            .build()
            .map_err(|e| KERIError::DatabaseError(format!("{}", e)))?;

        let db =
            Baser::new(Arc::new(lmdber)).map_err(|e| KERIError::DatabaseError(format!("{}", e)))?;

        let revery = Revery::new(Arc::new(&db), None, None, Some(true), Some(false));

        assert!(revery.lax);
        assert!(!revery.local);
        assert_eq!(revery.cues.len(), 0);

        Ok(())
    }
}
