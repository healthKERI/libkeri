use crate::cesr::number::Number;
use crate::cesr::tholder::{Tholder, TholderSith};
use crate::cesr::{Versionage, VERSION};
use crate::keri::core::serdering::SadValue;
use crate::keri::db::basing::{KeyStateRecord, StateEERecord};
use crate::keri::{KERIError, Kinds};
use chrono;
use num_bigint::BigUint;
use std::error::Error;

/// Builder for creating key state event records
pub struct StateEventBuilder {
    pre: String,         // Identifier prefix qb64
    sn: u64,             // Sequence number of latest event
    pig: String,         // SAID qb64 of prior event
    dig: String,         // SAID qb64 of latest (current) event
    fn_: u64,            // First seen ordinal number of latest event
    eilk: String,        // Event type (ilk) of latest event
    keys: Vec<String>,   // qb64 signing keys
    eevt: StateEERecord, // Latest establishment event

    stamp: Option<String>,      // ISO-8601 timestamp
    sith: Option<TholderSith>,  // Current signing threshold
    ndigs: Vec<String>,         // Current signing key digests qb64
    nsith: Option<TholderSith>, // Next signing threshold
    toad: Option<usize>,        // Witness threshold
    wits: Vec<String>,          // Witness identifier prefixes qb64
    cnfg: Vec<String>,          // Configuration trait strings
    dpre: Option<String>,       // Delegator prefix if any
    version: String,            // KERI protocol version string
    kind: String,               // Serialization kind
    intive: bool,               // True to use int thresholds instead of hex
}

impl StateEventBuilder {
    /// Create a new StateEventBuilder with required fields
    pub fn new(
        pre: String,
        sn: u64,
        pig: String,
        dig: String,
        fn_: u64,
        eilk: String,
        keys: Vec<String>,
        eevt: StateEERecord,
    ) -> Self {
        StateEventBuilder {
            pre,
            sn,
            pig,
            dig,
            fn_,
            eilk,
            keys,
            eevt,
            stamp: None,
            sith: None,
            ndigs: Vec::new(),
            nsith: None,
            toad: None,
            wits: Vec::new(),
            cnfg: Vec::new(),
            dpre: None,
            version: VERSION.to_string(),
            kind: Kinds::Json.to_string(),
            intive: false,
        }
    }

    /// Set the timestamp
    pub fn with_stamp(mut self, stamp: String) -> Self {
        self.stamp = Some(stamp);
        self
    }

    /// Set the signing threshold
    pub fn with_sith(mut self, sith: TholderSith) -> Self {
        self.sith = Some(sith);
        self
    }

    /// Set the next key digests
    pub fn with_ndigs(mut self, ndigs: Vec<String>) -> Self {
        self.ndigs = ndigs;
        self
    }

    /// Set the next signing threshold
    pub fn with_nsith(mut self, nsith: TholderSith) -> Self {
        self.nsith = Some(nsith);
        self
    }

    /// Set the witness threshold
    pub fn with_toad(mut self, toad: usize) -> Self {
        self.toad = Some(toad);
        self
    }

    /// Set the witnesses
    pub fn with_wits(mut self, wits: Vec<String>) -> Self {
        self.wits = wits;
        self
    }

    /// Set the configuration traits
    pub fn with_cnfg(mut self, cnfg: Vec<String>) -> Self {
        self.cnfg = cnfg;
        self
    }

    /// Set the delegator prefix
    pub fn with_dpre(mut self, dpre: String) -> Self {
        self.dpre = Some(dpre);
        self
    }

    /// Set the version
    pub fn with_version(mut self, version: String) -> Self {
        self.version = version;
        self
    }

    /// Set the serialization kind
    pub fn with_kind(mut self, kind: String) -> Self {
        self.kind = kind;
        self
    }

    /// Set whether to use integer thresholds
    pub fn with_intive(mut self, intive: bool) -> Self {
        self.intive = intive;
        self
    }

    /// Build the KeyStateRecord
    pub fn build(self) -> Result<KeyStateRecord, Box<dyn Error>> {
        // Validate sequence numbers
        let sner = Number::from_num(&BigUint::from(self.sn))?;
        let fner = Number::from_num(&BigUint::from(self.fn_))?;

        // Validate event type
        if !matches!(self.eilk.as_str(), "icp" | "rot" | "ixn" | "dip" | "drt") {
            return Err(Box::new(KERIError::ValueError(format!(
                "Invalid event type et={} in key state.",
                self.eilk
            ))));
        }

        // Generate timestamp if not provided
        let stamp = self.stamp.unwrap_or_else(|| {
            chrono::Utc::now()
                .format("%Y-%m-%dT%H:%M:%S%.6fZ")
                .to_string()
        });

        // Calculate default sith if not provided
        let tholder = if let Some(sith) = self.sith {
            Tholder::new(None, None, Some(sith))?
        } else {
            let default_sith = format!(
                "{:x}",
                std::cmp::max(1, (self.keys.len() as f64 / 2.0).ceil() as usize)
            );
            Tholder::new(
                None,
                None,
                Some(TholderSith::from_sad_value(SadValue::String(default_sith))?),
            )?
        };

        // Validate sith
        if let Some(num) = tholder.num() {
            if num < 1 {
                return Err(Box::new(KERIError::ValueError(format!(
                    "Invalid sith = {} less than 1.",
                    num
                ))));
            }
        }
        if tholder.size() > self.keys.len() {
            return Err(Box::new(KERIError::ValueError(format!(
                "Invalid sith = {:?} for keys = {:?}",
                tholder.sith(),
                self.keys
            ))));
        }

        // Calculate default nsith if not provided
        let ntholder = if let Some(nsith) = self.nsith {
            Tholder::new(None, None, Some(nsith))?
        } else {
            let default_nsith = format!(
                "{:x}",
                std::cmp::max(0, (self.ndigs.len() as f64 / 2.0).ceil() as usize)
            );
            Tholder::new(
                None,
                None,
                Some(TholderSith::from_sad_value(SadValue::String(
                    default_nsith,
                ))?),
            )?
        };

        // Validate nsith
        if ntholder.size() > self.ndigs.len() {
            return Err(Box::new(KERIError::ValueError(format!(
                "Invalid nsith = {:?} for ndigs = {:?}",
                ntholder.sith(),
                self.ndigs
            ))));
        }

        // Check for witness duplicates
        let wit_set: std::collections::HashSet<&String> = self.wits.iter().collect();
        if wit_set.len() != self.wits.len() {
            return Err(Box::new(KERIError::ValueError(format!(
                "Invalid wits = {:?}, has duplicates.",
                self.wits
            ))));
        }

        // Calculate default toad if not provided
        let toader = if let Some(toad) = self.toad {
            Number::from_num(&BigUint::from(toad))?
        } else {
            if self.wits.is_empty() {
                Number::from_num(&BigUint::from(0u32))?
            } else {
                let default_toad = std::cmp::max(1, (self.wits.len() as f64 / 2.0).ceil() as usize);
                Number::from_num(&BigUint::from(default_toad))?
            }
        };

        // Validate toad
        if !self.wits.is_empty() {
            if toader.num() < 1 || toader.num() as usize > self.wits.len() {
                return Err(Box::new(KERIError::ValueError(format!(
                    "Invalid toad = {} for wits = {:?}",
                    toader.num(),
                    self.wits
                ))));
            }
        } else {
            if toader.num() != 0 {
                return Err(Box::new(KERIError::ValueError(format!(
                    "Invalid toad = {} for empty wits",
                    toader.num()
                ))));
            }
        }

        // Validate eevt
        let eesner = Number::from_numh(&self.eevt.s)?;

        // Validate cuts (witness removals)
        let cuts = self.eevt.br.clone().unwrap_or_default();
        let cut_set: std::collections::HashSet<&String> = cuts.iter().collect();
        if cut_set.len() != cuts.len() {
            return Err(Box::new(KERIError::ValueError(format!(
                "Invalid cuts = {:?}, has duplicates in latest est event.",
                cuts
            ))));
        }

        // Validate adds (witness additions)
        let adds = self.eevt.ba.clone().unwrap_or_default();
        let add_set: std::collections::HashSet<&String> = adds.iter().collect();
        if add_set.len() != adds.len() {
            return Err(Box::new(KERIError::ValueError(format!(
                "Invalid adds = {:?}, has duplicates in latest est event.",
                adds
            ))));
        }

        // Check for intersection between cuts and adds
        let mut intersect = false;
        for cut in &cuts {
            if add_set.contains(&cut) {
                intersect = true;
                break;
            }
        }
        if intersect {
            return Err(Box::new(KERIError::ValueError(format!(
                "Intersecting cuts = {:?} and adds = {:?} in latest est event.",
                cuts, adds
            ))));
        }

        // Define constant for max integer threshold
        const MAX_INT_THOLD: usize = 2 ^ 32 - 1;

        // Build the KeyStateRecord
        let ksr = KeyStateRecord {
            vn: Versionage::from(self.version).to_vec(),
            i: self.pre,
            s: sner.numh(),
            p: self.pig,
            d: self.dig,
            f: fner.numh(),
            dt: stamp,
            et: self.eilk,
            kt: if self.intive && tholder.num().is_some() && tholder.num().unwrap() <= MAX_INT_THOLD
            {
                tholder.num().unwrap().to_string()
            } else {
                tholder.sith().to_string()
            },
            k: self.keys,
            nt: if self.intive
                && ntholder.num().is_some()
                && ntholder.num().unwrap() <= MAX_INT_THOLD
            {
                ntholder.num().unwrap().to_string()
            } else {
                ntholder.sith().to_string()
            },
            n: self.ndigs,
            bt: if self.intive && toader.num() <= MAX_INT_THOLD as u128 {
                toader.num().to_string()
            } else {
                toader.numh()
            },
            b: self.wits,
            c: self.cnfg,
            ee: self.eevt,
            di: self.dpre.unwrap_or_default(),
        };

        Ok(ksr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_state_event_builder_basic() -> Result<(), Box<dyn Error>> {
        let eevt = StateEERecord {
            s: "0".to_string(),
            d: "EXwm3_T3cINe-7R4FXQYcjKMr1cwrD7evf-i3k_oYrVM".to_string(),
            br: None,
            ba: None,
        };

        let keys = vec![
            "DXwm3_T3cINe-7R4FXQYcjKMr1cwrD7evf-i3k_oYrVM".to_string(),
            "EXwm3_T3cINe-7R4FXQYcjKMr1cwrD7evf-i3k_oYrVM".to_string(),
        ];

        let state = StateEventBuilder::new(
            "EXwm3_T3cINe-7R4FXQYcjKMr1cwrD7evf-i3k_oYrVM".to_string(),
            1,
            "AbcdefghijklmnopqrstuvwxyzABCDEFGHIJK".to_string(),
            "EXwm3_T3cINe-7R4FXQYcjKMr1cwrD7evf-i3k_oYrVM".to_string(),
            0,
            "icp".to_string(),
            keys.clone(),
            eevt,
        )
        .build()?;

        assert_eq!(state.i, "EXwm3_T3cINe-7R4FXQYcjKMr1cwrD7evf-i3k_oYrVM");
        assert_eq!(state.s, "1");
        assert_eq!(state.et, "icp");
        assert_eq!(state.k, keys);

        Ok(())
    }

    #[test]
    fn test_state_event_builder_with_wits() -> Result<(), Box<dyn Error>> {
        let eevt = StateEERecord {
            s: "0".to_string(),
            d: "EXwm3_T3cINe-7R4FXQYcjKMr1cwrD7evf-i3k_oYrVM".to_string(),
            br: Some(vec![
                "BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo".to_string()
            ]),
            ba: Some(vec![
                "BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw".to_string()
            ]),
        };

        let wits = vec![
            "BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo".to_string(),
            "BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw".to_string(),
        ];

        let state = StateEventBuilder::new(
            "EXwm3_T3cINe-7R4FXQYcjKMr1cwrD7evf-i3k_oYrVM".to_string(),
            1,
            "AbcdefghijklmnopqrstuvwxyzABCDEFGHIJK".to_string(),
            "EXwm3_T3cINe-7R4FXQYcjKMr1cwrD7evf-i3k_oYrVM".to_string(),
            0,
            "rot".to_string(),
            vec!["DXwm3_T3cINe-7R4FXQYcjKMr1cwrD7evf-i3k_oYrVM".to_string()],
            eevt,
        )
        .with_wits(wits.clone())
        .with_toad(2)
        .build()?;

        assert_eq!(state.et, "rot");
        assert_eq!(state.b, wits);
        assert_eq!(state.bt, "2");

        Ok(())
    }

    #[test]
    fn test_state_event_builder_with_delegation() -> Result<(), Box<dyn Error>> {
        let eevt = StateEERecord {
            s: "0".to_string(),
            d: "EXwm3_T3cINe-7R4FXQYcjKMr1cwrD7evf-i3k_oYrVM".to_string(),
            br: None,
            ba: None,
        };

        let state = StateEventBuilder::new(
            "EXwm3_T3cINe-7R4FXQYcjKMr1cwrD7evf-i3k_oYrVM".to_string(),
            1,
            "AbcdefghijklmnopqrstuvwxyzABCDEFGHIJK".to_string(),
            "EXwm3_T3cINe-7R4FXQYcjKMr1cwrD7evf-i3k_oYrVM".to_string(),
            0,
            "dip".to_string(),
            vec!["DXwm3_T3cINe-7R4FXQYcjKMr1cwrD7evf-i3k_oYrVM".to_string()],
            eevt,
        )
        .with_dpre("EZAoTNZH3ULvaU6Z-i0d8JJR2nmwyYAfSVPzhzS6b5CM".to_string())
        .build()?;

        assert_eq!(state.et, "dip");
        assert_eq!(state.di, "EZAoTNZH3ULvaU6Z-i0d8JJR2nmwyYAfSVPzhzS6b5CM");

        Ok(())
    }

    #[test]
    fn test_state_event_builder_with_intive() -> Result<(), Box<dyn Error>> {
        let eevt = StateEERecord {
            s: "0".to_string(),
            d: "EXwm3_T3cINe-7R4FXQYcjKMr1cwrD7evf-i3k_oYrVM".to_string(),
            br: None,
            ba: None,
        };

        let state = StateEventBuilder::new(
            "EXwm3_T3cINe-7R4FXQYcjKMr1cwrD7evf-i3k_oYrVM".to_string(),
            1,
            "AbcdefghijklmnopqrstuvwxyzABCDEFGHIJK".to_string(),
            "EXwm3_T3cINe-7R4FXQYcjKMr1cwrD7evf-i3k_oYrVM".to_string(),
            0,
            "icp".to_string(),
            vec![
                "DXwm3_T3cINe-7R4FXQYcjKMr1cwrD7evf-i3k_oYrVM".to_string(),
                "EXwm3_T3cINe-7R4FXQYcjKMr1cwrD7evf-i3k_oYrVM".to_string(),
            ],
            eevt,
        )
        .with_intive(true)
        .with_sith(TholderSith::Integer(1))
        .build()?;

        assert_eq!(state.kt, "1");

        Ok(())
    }
}
