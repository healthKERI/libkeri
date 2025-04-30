use crate::cesr::number::Number;
use crate::cesr::tholder::{Tholder, TholderSith};
use crate::cesr::Versionage;
use crate::keri::core::eventing::{ample, is_digest_code, is_prefix_code, MAX_INT_THOLD};
use crate::keri::core::serdering::{SadValue, Sadder, SerderKERI};
use crate::keri::versify;
use num_bigint::BigUint;
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::error::Error;

/// Builder for creating SerderKERI inception events
pub struct InceptionEventBuilder {
    // Required parameters
    keys: Vec<String>,

    // Optional parameters with defaults
    isith: Option<TholderSith>,
    ndigs: Vec<String>,
    nsith: Option<TholderSith>,
    toad: Option<usize>,
    wits: Vec<String>,
    cnfg: Vec<String>,
    data: Vec<SadValue>,
    version: String,
    kind: String,
    code: Option<String>,
    intive: bool,
    delpre: Option<String>,
}

impl InceptionEventBuilder {
    /// Creates a new InceptionEventBuilder with default values
    pub fn new(keys: Vec<String>) -> Self {
        InceptionEventBuilder {
            keys,
            isith: None,
            ndigs: Vec::new(),
            nsith: None,
            toad: None,
            wits: Vec::new(),
            cnfg: Vec::new(),
            data: Vec::new(),
            version: "KERI10JSON000000_".to_string(), // Default version
            kind: "JSON".to_string(),                 // Default kind
            code: None,
            intive: false,
            delpre: None,
        }
    }

    /// Sets the initial signing threshold (isith)
    pub fn with_isith(mut self, isith: TholderSith) -> Self {
        self.isith = Some(isith);
        self
    }

    /// Sets the next signing key digests (ndigs)
    pub fn with_ndigs(mut self, ndigs: Vec<String>) -> Self {
        self.ndigs = ndigs;
        self
    }

    /// Sets the next signing threshold (nsith)
    pub fn with_nsith(mut self, nsith: TholderSith) -> Self {
        self.nsith = Some(nsith);
        self
    }

    /// Sets the witness threshold (toad)
    pub fn with_toad(mut self, toad: usize) -> Self {
        self.toad = Some(toad);
        self
    }

    /// Sets the witnesses (wits)
    pub fn with_wits(mut self, wits: Vec<String>) -> Self {
        self.wits = wits;
        self
    }

    /// Sets the configuration traits (cnfg)
    pub fn with_cnfg(mut self, cnfg: Vec<String>) -> Self {
        self.cnfg = cnfg;
        self
    }

    /// Sets the data (seal dicts)
    pub fn with_data(mut self, data: Vec<SadValue>) -> Self {
        self.data = data;
        self
    }

    /// Sets the version
    pub fn with_version(mut self, version: String) -> Self {
        self.version = version;
        self
    }

    /// Sets the serialization kind
    pub fn with_kind(mut self, kind: String) -> Self {
        self.kind = kind;
        self
    }

    /// Sets the derivation code for computed prefix
    pub fn with_code(mut self, code: String) -> Self {
        self.code = Some(code);
        self
    }

    /// Sets whether to use integer representation for thresholds
    pub fn with_intive(mut self, intive: bool) -> Self {
        self.intive = intive;
        self
    }

    /// Sets the delegator identifier prefix
    pub fn with_delpre(mut self, delpre: String) -> Self {
        self.delpre = Some(delpre);
        self
    }

    /// Builds the SerderKERI inception event
    pub fn build(self) -> Result<SerderKERI, Box<dyn Error>> {
        // Version string
        let vs = versify("KERI", &Versionage::from(self.version), &self.kind, 0)?;

        // Determine ilk based on delpre
        let ilk = if self.delpre.is_none() { "icp" } else { "dip" };

        // Create sner (sequence number) - must be 0 for inception
        let sner = Number::from_num(&BigUint::from(0u32))?;

        // Process isith
        let isith = match self.isith {
            Some(sith) => sith,
            None => {
                // Default to max(1, ceil(len(keys) / 2))
                let default_threshold =
                    std::cmp::max(1, (self.keys.len() as f64 / 2.0).ceil() as usize);
                TholderSith::Integer(default_threshold)
            }
        };

        // Create and validate tholder
        let tholder = Tholder::new(None, None, Some(isith.clone()))?;
        if let Some(num) = tholder.num() {
            if num < 1 {
                return Err(format!("Invalid sith = {} less than 1.", num).into());
            }
        }
        if tholder.size() > self.keys.len() {
            return Err(format!("Invalid sith = {:?} for keys = {:?}", isith, self.keys).into());
        }

        // Process nsith
        let nsith = match self.nsith {
            Some(sith) => sith,
            None => {
                // Default to max(0, ceil(len(ndigs) / 2))
                let default_threshold =
                    std::cmp::max(0, (self.ndigs.len() as f64 / 2.0).ceil() as usize);
                TholderSith::Integer(default_threshold)
            }
        };

        // Create and validate ntholder
        let ntholder = Tholder::new(None, None, Some(nsith.clone()))?;
        if ntholder.size() > self.ndigs.len() {
            return Err(format!("Invalid nsith = {:?} for ndigs = {:?}", nsith, self.ndigs).into());
        }

        // Process witnesses
        let wits = self.wits;

        // Check for duplicates in wits
        let wits_set: HashSet<_> = wits.iter().cloned().collect();
        if wits_set.len() != wits.len() {
            return Err(format!("Invalid wits = {:?}, has duplicates.", wits).into());
        }

        // Process toad
        let toad = match self.toad {
            Some(t) => t,
            None => {
                if wits.is_empty() {
                    0
                } else {
                    // Compute default threshold using ample function
                    ample(wits.len())
                }
            }
        };

        // Create toader
        let toader = Number::from_num(&BigUint::from(toad))?;

        // Validate toad
        if !wits.is_empty() {
            if toader.num() < 1 || toader.num() > wits.len() as u128 {
                return Err(
                    format!("Invalid toad = {} for wits = {:?}", toader.num(), wits).into(),
                );
            }
        } else if toader.num() != 0 {
            return Err(format!("Invalid toad = {} for wits = {:?}", toader.num(), wits).into());
        }

        let kt =
            if self.intive && tholder.num().is_some() && tholder.num().unwrap() <= MAX_INT_THOLD {
                Value::Number(serde_json::Number::from(tholder.num().unwrap() as u64))
            } else {
                match &tholder.sith() {
                    TholderSith::Integer(n) => Value::Number(serde_json::Number::from(*n as u64)),
                    TholderSith::HexString(s) => Value::String(s.clone()),
                    TholderSith::Json(s) => serde_json::from_str(s)?,
                    TholderSith::Weights(w) => serde_json::to_value(w)?,
                }
            };

        let nt = if self.intive
            && ntholder.num().is_some()
            && ntholder.num().unwrap() <= MAX_INT_THOLD
        {
            Value::Number(serde_json::Number::from(ntholder.num().unwrap() as u64))
        } else {
            match &ntholder.sith() {
                TholderSith::Integer(n) => Value::Number(serde_json::Number::from(*n as u64)),
                TholderSith::HexString(s) => Value::String(s.clone()),
                TholderSith::Json(s) => serde_json::from_str(s)?,
                TholderSith::Weights(w) => serde_json::to_value(w)?,
            }
        };

        let bt = if self.intive && toader.num() <= MAX_INT_THOLD as u128 {
            Value::Number(serde_json::Number::from(toader.num() as u64))
        } else {
            Value::String(toader.numh().to_string())
        };

        // Create a new Sadder object for the KED (Key Event Data)
        let mut ked = Sadder::default();

        // Set the required fields
        ked.insert("v".to_string(), SadValue::String(vs));
        ked.insert("t".to_string(), SadValue::String(ilk.to_string()));
        ked.insert("d".to_string(), SadValue::String(String::new())); // qb64 SAID (empty for now)
        ked.insert("i".to_string(), SadValue::String(String::new())); // qb64 prefix (empty for now)
        ked.insert("s".to_string(), SadValue::String(sner.numh())); // hex string no leading zeros lowercase

        match kt {
            Value::Number(n) => {
                if let Some(n_u64) = n.as_u64() {
                    ked.insert("kt".to_string(), SadValue::Number(n));
                }
            }
            Value::String(s) => {
                ked.insert("kt".to_string(), SadValue::String(s.to_string()));
                ()
            }
            _ => {
                if let Some(num) = tholder.num() {
                    ked.insert("kt".to_string(), SadValue::String(num.to_string()));
                } else {
                    ked.insert("kt".to_string(), SadValue::String(kt.to_string()));
                }
            }
        };

        // Set the keys list
        let key_values = self
            .keys
            .iter()
            .map(|k| SadValue::String(k.clone()))
            .collect();
        ked.insert("k".to_string(), SadValue::Array(key_values)); // list of qb64

        // Set next threshold
        match nt {
            Value::Number(n) => {
                if let Some(n_u64) = n.as_u64() {
                    ked.insert("nt".to_string(), SadValue::Number(n));
                }
            }
            Value::String(s) => {
                ked.insert("nt".to_string(), SadValue::String(s));
                ()
            }
            _ => {
                if let Some(num) = ntholder.num() {
                    ked.insert("nt".to_string(), SadValue::String(num.to_string()));
                } else {
                    ked.insert("nt".to_string(), SadValue::String(nt.to_string()));
                }
            }
        };

        // Set next digests list
        let ndig_values = self
            .ndigs
            .iter()
            .map(|n| SadValue::String(n.clone()))
            .collect();
        ked.insert("n".to_string(), SadValue::Array(ndig_values)); // list of qb64

        // Set witness threshold
        match bt {
            Value::Number(n) => {
                if let Some(n_u64) = n.as_u64() {
                    ked.insert("bt".to_string(), SadValue::Number(n));
                }
            }
            Value::String(s) => {
                ked.insert("bt".to_string(), SadValue::String(s));
                ()
            }
            _ => {
                ked.insert(
                    "bt".to_string(),
                    SadValue::String(toader.numh().to_string()),
                );
                ()
            }
        };

        // Set witnesses list
        let wit_values = wits.iter().map(|w| SadValue::String(w.clone())).collect();
        ked.insert("b".to_string(), SadValue::Array(wit_values)); // list of qb64

        // Set config traits
        let cnfg_values = self
            .cnfg
            .iter()
            .map(|c| SadValue::String(c.clone()))
            .collect();
        ked.insert("c".to_string(), SadValue::Array(cnfg_values)); // list of config ordered mappings may be empty

        // Set data (seal dicts)
        if !self.data.is_empty() {
            ked.insert("a".to_string(), SadValue::Array(self.data.clone())); // list of config ordered mappings may be empty
        }

        // Handle delegated inception
        if let Some(delpre) = self.delpre.clone() {
            ked.insert("di".to_string(), SadValue::String(delpre.clone()));
        } else {
            // Non-delegated inception
            if (self.code.is_none() || !is_digest_code(&self.code.as_ref().unwrap()))
                && self.keys.len() == 1
            {
                // Use first key as default identifier
                ked.insert("i".to_string(), SadValue::String(self.keys[0].clone()));
            }
        }

        // Create a HashMap for saids if needed
        let mut saids_map = None;
        if let Some(ref code) = self.code {
            if is_prefix_code(code) {
                let mut map = HashMap::new();
                map.insert("i", code.clone());
                saids_map = Some(map);
            }
        }

        // Handle delegated inception
        let mut saids = HashMap::new();
        // Use code to override all else if it's a prefix code
        if let Some(ref code) = self.code {
            if is_prefix_code(code) {
                saids.insert("i", code.to_string());
            }
        }

        // Create SerderKERI
        let serder = SerderKERI::from_sad_and_saids(&ked, Some(saids))?;
        Ok(serder)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cesr::diger::Diger;
    use crate::cesr::mtr_dex;
    use crate::cesr::signing::Signer;
    use crate::cesr::tholder::TholderSith;
    use crate::keri::core::serdering::Serder;
    use crate::keri::Ilks;
    use crate::Matter;
    use std::error::Error;

    #[test]
    fn test_inception_event_builder_non_transferable() -> Result<(), Box<dyn Error>> {
        // Setup a fixed seed similar to the Python test
        let seed = b"\x9f{\xa8\xa7\xa8C9\x96&\xfa\xb1\x99\xeb\xaa \xc4\x1bG\x11\xc4\xaeSAR\
             \xc9\xbd\x04\x9d\x85)~\x93";

        // Create a non-transferable signer (ephemeral case)
        let signer0 = Signer::new(Some(&seed[..]), Some(mtr_dex::ED25519_SEED), Some(false))?;
        assert_eq!(signer0.code(), mtr_dex::ED25519_SEED);
        assert_eq!(signer0.verfer().code(), mtr_dex::ED25519N);

        // Extract verfer qb64 for the key
        let keys0 = vec![signer0.verfer().qb64()];

        // Create inception event using the builder
        let serder = InceptionEventBuilder::new(keys0).build()?;

        // Verify the key event data
        let ked = serder.ked();

        let raw_str = std::str::from_utf8(serder.raw()).expect("Bad raw");

        // Check identifier matches our expectations
        assert_eq!(
            ked["i"].as_str(),
            Some("BFs8BBx86uytIM0D2BhsE5rrqVIT8ef8mflpNceHo4XH")
        );

        // Check next key digests are empty
        if let Some(ndigs) = ked["n"].as_array() {
            assert!(ndigs.is_empty());
        } else {
            assert!(true); // n is None which is also valid for empty
        }

        // Check the raw serialized form if needed
        // This may be challenging due to string serialization differences
        let raw = serder.raw();
        // Verify the content contains the expected elements
        // Instead of checking exact bytes, check for key elements
        assert_eq!(raw, b"{\"v\":\"KERI10JSON0000fd_\",\"t\":\"icp\",\"d\":\"EMW0zK3bagYPO6gx3w7Ua90f-I7x5kGIaI4X\
            eq9W8_As\",\"i\":\"BFs8BBx86uytIM0D2BhsE5rrqVIT8ef8mflpNceHo4XH\",\"s\":\"0\",\"kt\":\"1\
            \",\"k\":[\"BFs8BBx86uytIM0D2BhsE5rrqVIT8ef8mflpNceHo4XH\"],\"nt\":\"0\",\"n\":[],\"bt\":\
            \"0\",\"b\":[],\"c\":[],\"a\":[]}");
        Ok(())
    }

    #[test]
    fn test_inception_event_builder_with_thresholds() -> Result<(), Box<dyn Error>> {
        // Create multiple keys
        let keys = vec![
            "DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA".to_string(),
            "DVcuJOOJF1IE8svqEtrSuyQjGTd2HhfAkt9y2QkUtFJI".to_string(),
            "DT1iAhBWCkvChxNWsby2J0pJyxBIxbAtbLA0Ljx-Grh8".to_string(),
        ];

        let configs = vec!["EO".to_string()];

        // Create inception event with custom thresholds
        let serder = InceptionEventBuilder::new(keys.clone())
            .with_isith(TholderSith::Integer(2)) // 2 of 3 for current keys
            .with_ndigs(vec![
                "EGAPkzNZMtX-QiVgbRbyAIZGoXvbGv9IPb0foWTZvI_4".to_string(),
                "EIAQI--Q9LC48CM_ZyzjM-w-GfqkFkO-6lJ9klGt1fS8".to_string(),
            ])
            .with_nsith(TholderSith::Integer(1)) // 1 of 2 for next keys
            .with_wits(vec![
                "BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha".to_string(),
                "BLskRTInXnMxWaGqcpSyMgo0nYbalW99cGZESrz3zapM".to_string(),
            ])
            .with_toad(2) // Witness threshold
            .with_cnfg(configs) // Example config
            .build()?;

        // Verify the key event data
        let ked = serder.ked();

        assert_eq!(ked["v"].as_str(), Some("KERI10JSON000219_"));
        assert_eq!(ked["t"].as_str(), Some("icp"));
        assert_eq!(
            ked["d"].as_str(),
            Some("EBJ57YenBaTk-SvA5hDVf4KPKmotcKe-8imGK4bSu5xY")
        );
        assert_eq!(
            ked["i"].as_str(),
            Some("EBJ57YenBaTk-SvA5hDVf4KPKmotcKe-8imGK4bSu5xY")
        );

        // Verify key elements
        if let Some(k) = ked["k"].as_array() {
            let ks: Vec<String> = k.iter().map(|k| k.as_str().unwrap().to_string()).collect();
            assert_eq!(ks, keys);
        } else {
            panic!("Keys missing in KED");
        }

        // Verify thresholds
        assert_eq!(ked["kt"].as_str(), Some("2"));
        assert_eq!(ked["nt"].as_str(), Some("1"));
        assert_eq!(ked["bt"].as_str(), Some("2"));

        // Verify witnesses
        if let Some(wits) = ked["b"].as_array() {
            assert_eq!(wits.len(), 2);
            assert_eq!(
                wits[0],
                SadValue::String("BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha".to_string())
            );
            assert_eq!(
                wits[1],
                SadValue::String("BLskRTInXnMxWaGqcpSyMgo0nYbalW99cGZESrz3zapM".to_string())
            );
        } else {
            panic!("Witnesses missing in KED");
        }

        // Verify configs
        if let Some(configs) = ked["c"].as_array() {
            assert_eq!(configs.len(), 1);
            assert_eq!(configs[0], SadValue::String("EO".to_string()));
        } else {
            panic!("Config missing in KED");
        }

        Ok(())
    }

    #[test]
    fn test_inception_event_builder_delegation() -> Result<(), Box<dyn Error>> {
        // Create a delegated inception
        let delegator_prefix = "EP1JJCqTdVteCPBqhQ_MqIagD-cplDS_LXoQG-rDd6j4".to_string();

        let keys = vec!["DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA".to_string()];

        let serder = InceptionEventBuilder::new(keys)
            .with_delpre(delegator_prefix.clone())
            .build()?;

        // Verify the key event data
        let ked = serder.ked();

        // Check it's a delegated inception
        assert_eq!(ked["t"].as_str(), Some("dip"));

        // Check delegator prefix
        assert_eq!(ked["di"].as_str(), Some(delegator_prefix.as_str()));

        Ok(())
    }

    #[test]
    fn test_inception_transferable_case_abandoned() -> Result<(), Box<dyn Error>> {
        // Original signing keypair - transferable default
        let seed = b"\x9f{\xa8\xa7\xa8C9\x96&\xfa\xb1\x99\xeb\xaa \xc4\x1bG\x11\xc4\xaeSAR\
                     \xc9\xbd\x04\x9d\x85)~\x93";

        let signer0 = Signer::new(Some(seed), Some(mtr_dex::ED25519_SEED), Some(true))?;
        assert_eq!(signer0.code(), mtr_dex::ED25519_SEED);
        assert_eq!(signer0.verfer().code(), mtr_dex::ED25519);

        let keys0 = vec![signer0.verfer().qb64()];

        // Default nxt is empty so abandoned
        let serder = InceptionEventBuilder::new(keys0).build()?;

        assert_eq!(
            serder.ked()["i"].as_str().unwrap(),
            "DFs8BBx86uytIM0D2BhsE5rrqVIT8ef8mflpNceHo4XH"
        );
        assert!(serder.ked()["n"].as_array().unwrap().is_empty());

        assert_eq!(serder.raw(), b"{\"v\":\"KERI10JSON0000fd_\",\"t\":\"icp\",\"d\":\"EPLRRJFe2FHdXKVTkSEX4xb4x-YaPFJ2Xds1\
                                 vhtNTd4n\",\"i\":\"DFs8BBx86uytIM0D2BhsE5rrqVIT8ef8mflpNceHo4XH\",\"s\":\"0\",\"kt\":\"1\
                                 \",\"k\":[\"DFs8BBx86uytIM0D2BhsE5rrqVIT8ef8mflpNceHo4XH\"],\"nt\":\"0\",\"n\":[],\"bt\":\
                                 \"0\",\"b\":[],\"c\":[],\"a\":[]}");

        Ok(())
    }

    #[test]
    fn test_inception_transferable_not_abandoned_self_addressing() -> Result<(), Box<dyn Error>> {
        // Original signing keypair
        let seed = b"\x9f{\xa8\xa7\xa8C9\x96&\xfa\xb1\x99\xeb\xaa \xc4\x1bG\x11\xc4\xaeSAR\
                         \xc9\xbd\x04\x9d\x85)~\x93";

        let signer0 = Signer::new(Some(seed), Some(mtr_dex::ED25519_SEED), Some(true))?;
        let keys0 = vec![signer0.verfer().qb64()];

        // Next signing keypair - transferable default
        let seed1 = b"\x83B~\x04\x94\xe3\xceUQy\x11f\x0c\x93]\x1e\xbf\xacQ\xb5\xd6Y^\xa2E\xfa\x015\
                          \x98Y\xdd\xe8";

        let signer1 = Signer::new(Some(seed1), Some(mtr_dex::ED25519_SEED), Some(true))?;
        assert_eq!(signer1.code(), mtr_dex::ED25519_SEED);
        assert_eq!(signer1.verfer().code(), mtr_dex::ED25519);

        // Compute nxt digest
        let nxt1 =
            vec![Diger::from_ser(&signer1.verfer().qb64b(), Some(mtr_dex::BLAKE3_256))?.qb64()];
        assert_eq!(nxt1, vec!["EIf-ENw7PrM52w4H-S7NGU2qVIfraXVIlV9hEAaMHg7W"]);

        // Create inception event with self-addressing and nxt digest
        let serder0 = InceptionEventBuilder::new(keys0.clone())
            .with_ndigs(nxt1.clone())
            .with_code(mtr_dex::BLAKE3_256.to_string())
            .build()?;

        let ked = serder0.ked();
        let pre = ked["i"].as_str().unwrap();
        assert_eq!(ked["t"].as_str().unwrap(), Ilks::ICP);
        assert_eq!(ked["d"].as_str().unwrap(), pre);
        assert_eq!(pre, "EAKCxMOuoRzREVHsHCkLilBrUXTvyenBiuM2QtV8BB0C");
        assert_eq!(ked["s"].as_str().unwrap(), "0");
        assert_eq!(ked["kt"].as_str().unwrap(), "1");
        assert_eq!(ked["nt"].as_str().unwrap(), "1");
        assert_eq!(ked["n"].as_array().unwrap()[0].as_str().unwrap(), nxt1[0]);
        assert_eq!(ked["bt"].as_str().unwrap(), "0");

        assert_eq!(serder0.raw(), b"{\"v\":\"KERI10JSON00012b_\",\"t\":\"icp\",\"d\":\"EAKCxMOuoRzREVHsHCkLilBrUXTvyenBiuM2\
                                       QtV8BB0C\",\"i\":\"EAKCxMOuoRzREVHsHCkLilBrUXTvyenBiuM2QtV8BB0C\",\"s\":\"0\",\"kt\":\"1\
                                       \",\"k\":[\"DFs8BBx86uytIM0D2BhsE5rrqVIT8ef8mflpNceHo4XH\"],\"nt\":\"1\",\"n\":[\"EIf-EN\
                                       w7PrM52w4H-S7NGU2qVIfraXVIlV9hEAaMHg7W\"],\"bt\":\"0\",\"b\":[],\"c\":[],\"a\":[]}");

        Ok(())
    }

    #[test]
    fn test_inception_transferable_not_abandoned_self_addressing_intive(
    ) -> Result<(), Box<dyn Error>> {
        // Original signing keypair
        let seed = b"\x9f{\xa8\xa7\xa8C9\x96&\xfa\xb1\x99\xeb\xaa \xc4\x1bG\x11\xc4\xaeSAR\
                         \xc9\xbd\x04\x9d\x85)~\x93";

        let signer0 = Signer::new(Some(seed), Some(mtr_dex::ED25519_SEED), Some(true))?;
        let keys0 = vec![signer0.verfer().qb64()];

        // Next signing keypair - transferable default
        let seed1 = b"\x83B~\x04\x94\xe3\xceUQy\x11f\x0c\x93]\x1e\xbf\xacQ\xb5\xd6Y^\xa2E\xfa\x015\
                          \x98Y\xdd\xe8";

        let signer1 = Signer::new(Some(seed1), Some(mtr_dex::ED25519_SEED), Some(true))?;
        assert_eq!(signer1.code(), mtr_dex::ED25519_SEED);
        assert_eq!(signer1.verfer().code(), mtr_dex::ED25519);

        // Compute nxt digest
        let nxt1 =
            vec![Diger::from_ser(&signer1.verfer().qb64b(), Some(mtr_dex::BLAKE3_256))?.qb64()];
        assert_eq!(nxt1, vec!["EIf-ENw7PrM52w4H-S7NGU2qVIfraXVIlV9hEAaMHg7W"]);

        // Create inception event with self-addressing, nxt digest, and intive=true
        let serder0 = InceptionEventBuilder::new(keys0.clone())
            .with_ndigs(nxt1.clone())
            .with_code(mtr_dex::BLAKE3_256.to_string())
            .with_intive(true)
            .build()?;

        let raw_str = std::str::from_utf8(serder0.raw())?;

        let ked = serder0.ked();
        let pre = ked["i"].as_str().unwrap();
        assert_eq!(ked["t"].as_str().unwrap(), Ilks::ICP);
        assert_eq!(ked["d"].as_str().unwrap(), pre);
        assert_eq!(pre, "EIflL4H4134zYoRM6ls6Q086RLC_BhfNFh5uk-WxvhsL");
        assert_eq!(ked["s"].as_str().unwrap(), "0");
        assert!(ked["kt"].is_number()); // Number instead of string
        assert!(ked["nt"].is_number()); // Number instead of string
        assert_eq!(ked["n"].as_array().unwrap()[0].as_str().unwrap(), nxt1[0]);
        assert!(ked["bt"].is_number()); // Number instead of string

        assert_eq!(serder0.raw(), b"{\"v\":\"KERI10JSON000125_\",\"t\":\"icp\",\"d\":\"EIflL4H4134zYoRM6ls6Q086RLC_BhfNFh5u\
                           k-WxvhsL\",\"i\":\"EIflL4H4134zYoRM6ls6Q086RLC_BhfNFh5uk-WxvhsL\",\"s\":\"0\",\"kt\":1,\
                           \"k\":[\"DFs8BBx86uytIM0D2BhsE5rrqVIT8ef8mflpNceHo4XH\"],\"nt\":1,\"n\":[\"EIf-ENw7Pr\
                           M52w4H-S7NGU2qVIfraXVIlV9hEAaMHg7W\"],\"bt\":0,\"b\":[],\"c\":[],\"a\":[]}");

        Ok(())
    }

    #[test]
    fn test_inception_transferable_not_abandoned_intive_true() -> Result<(), Box<dyn Error>> {
        // Original signing keypair
        let seed = b"\x9f{\xa8\xa7\xa8C9\x96&\xfa\xb1\x99\xeb\xaa \xc4\x1bG\x11\xc4\xaeSAR\
                         \xc9\xbd\x04\x9d\x85)~\x93";

        let signer0 = Signer::new(Some(seed), Some(mtr_dex::ED25519_SEED), Some(true))?;
        let keys0 = vec![signer0.verfer().qb64()];

        // Next signing keypair - transferable default
        let seed1 = b"\x83B~\x04\x94\xe3\xceUQy\x11f\x0c\x93]\x1e\xbf\xacQ\xb5\xd6Y^\xa2E\xfa\x015\
                          \x98Y\xdd\xe8";

        let signer1 = Signer::new(Some(seed1), Some(mtr_dex::ED25519_SEED), Some(true))?;
        assert_eq!(signer1.code(), mtr_dex::ED25519_SEED);
        assert_eq!(signer1.verfer().code(), mtr_dex::ED25519);

        // Compute nxt digest
        let nxt1 =
            vec![Diger::from_ser(&signer1.verfer().qb64b(), Some(mtr_dex::BLAKE3_256))?.qb64()];
        assert_eq!(nxt1, vec!["EIf-ENw7PrM52w4H-S7NGU2qVIfraXVIlV9hEAaMHg7W"]);

        // Create inception event with nxt digest and intive=true
        let serder0 = InceptionEventBuilder::new(keys0.clone())
            .with_ndigs(nxt1.clone())
            .with_intive(true)
            .build()?;

        let ked = serder0.ked();
        assert_eq!(ked["t"].as_str().unwrap(), Ilks::ICP);
        assert_eq!(
            ked["i"].as_str().unwrap(),
            "DFs8BBx86uytIM0D2BhsE5rrqVIT8ef8mflpNceHo4XH"
        );
        assert_eq!(ked["s"].as_str().unwrap(), "0");
        assert!(ked["kt"].is_number()); // Number instead of string
        assert!(ked["nt"].is_number()); // Number instead of string
        assert_eq!(ked["n"].as_array().unwrap()[0].as_str().unwrap(), nxt1[0]);
        assert!(ked["bt"].is_number()); // Integer instead of string

        assert_eq!(serder0.raw(), b"{\"v\":\"KERI10JSON000125_\",\"t\":\"icp\",\"d\":\"EFSJqZE0K0WU95dmccrg_8EKSuVSrt4kGIZN\
                           jqWFA_HL\",\"i\":\"DFs8BBx86uytIM0D2BhsE5rrqVIT8ef8mflpNceHo4XH\",\"s\":\"0\",\"kt\":1,\
                           \"k\":[\"DFs8BBx86uytIM0D2BhsE5rrqVIT8ef8mflpNceHo4XH\"],\"nt\":1,\"n\":[\"EIf-ENw7Pr\
                           M52w4H-S7NGU2qVIfraXVIlV9hEAaMHg7W\"],\"bt\":0,\"b\":[],\"c\":[],\"a\":[]}");
        Ok(())
    }

    #[test]
    fn test_inception_transferable_not_abandoned() -> Result<(), Box<dyn Error>> {
        // Original signing keypair
        let seed = b"\x9f{\xa8\xa7\xa8C9\x96&\xfa\xb1\x99\xeb\xaa \xc4\x1bG\x11\xc4\xaeSAR\
                         \xc9\xbd\x04\x9d\x85)~\x93";

        let signer0 = Signer::new(Some(seed), Some(mtr_dex::ED25519_SEED), Some(true))?;
        let keys0 = vec![signer0.verfer().qb64()];

        // Next signing keypair - transferable default
        let seed1 = b"\x83B~\x04\x94\xe3\xceUQy\x11f\x0c\x93]\x1e\xbf\xacQ\xb5\xd6Y^\xa2E\xfa\x015\
                          \x98Y\xdd\xe8";

        let signer1 = Signer::new(Some(seed1), Some(mtr_dex::ED25519_SEED), Some(true))?;
        assert_eq!(signer1.code(), mtr_dex::ED25519_SEED);
        assert_eq!(signer1.verfer().code(), mtr_dex::ED25519);

        // Compute nxt digest
        let nxt1 =
            vec![Diger::from_ser(&signer1.verfer().qb64b(), Some(mtr_dex::BLAKE3_256))?.qb64()];
        assert_eq!(nxt1, vec!["EIf-ENw7PrM52w4H-S7NGU2qVIfraXVIlV9hEAaMHg7W"]);

        // Create inception event with nxt digest
        let serder0 = InceptionEventBuilder::new(keys0.clone())
            .with_ndigs(nxt1.clone())
            .build()?;

        let ked = serder0.ked();
        assert_eq!(ked["t"].as_str().unwrap(), Ilks::ICP);
        assert_eq!(
            ked["i"].as_str().unwrap(),
            "DFs8BBx86uytIM0D2BhsE5rrqVIT8ef8mflpNceHo4XH"
        );
        assert_eq!(ked["s"].as_str().unwrap(), "0");
        assert_eq!(ked["kt"].as_str().unwrap(), "1");
        assert_eq!(ked["nt"].as_str().unwrap(), "1");
        assert_eq!(ked["n"].as_array().unwrap()[0].as_str().unwrap(), nxt1[0]);
        assert_eq!(ked["bt"].as_str().unwrap(), "0");

        assert_eq!(serder0.raw(), b"{\"v\":\"KERI10JSON00012b_\",\"t\":\"icp\",\"d\":\"EJQUyxnzIAtmZPoq9f4fExeGN0qfJmaFnUEK\
                               TwIiTBPj\",\"i\":\"DFs8BBx86uytIM0D2BhsE5rrqVIT8ef8mflpNceHo4XH\",\"s\":\"0\",\"kt\":\"1\
                               \",\"k\":[\"DFs8BBx86uytIM0D2BhsE5rrqVIT8ef8mflpNceHo4XH\"],\"nt\":\"1\",\"n\":[\"EIf-EN\
                               w7PrM52w4H-S7NGU2qVIfraXVIlV9hEAaMHg7W\"],\"bt\":\"0\",\"b\":[],\"c\":[],\"a\":[]}");

        Ok(())
    }
}
