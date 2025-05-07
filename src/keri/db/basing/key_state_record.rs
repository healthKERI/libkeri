use crate::keri::core::serdering::SadValue;
use crate::keri::KERIError;
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use std::default::Default;

/// Corresponds to StateEstEvent namedtuple used as sub record in KeyStateRecord
/// for latest establishment event associated with current key state
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateEERecord {
    /// Sequence number of latest est evt lowercase hex no leading zeros
    #[serde(default = "default_sequence_number")]
    pub s: String,

    /// SAID qb64 of latest est evt
    #[serde(default)]
    pub d: String,

    /// Backer aids qb64 remove list (cuts) from latest est event
    #[serde(default)]
    pub br: Option<Vec<String>>,

    /// Backer aids qb64 add list (adds) from latest est event
    #[serde(default)]
    pub ba: Option<Vec<String>>,
}

/// Key State information keyed by Identifier Prefix of associated KEL.
/// For local AIDs that correspond to Habs this is the Hab AID.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyStateRecord {
    /// Version number [major, minor]
    #[serde(default)]
    pub vn: Vec<u8>,

    /// Identifier prefix qb64
    #[serde(default)]
    pub i: String,

    /// Sequence number of latest event in KEL as hex str
    #[serde(default = "default_sequence_number")]
    pub s: String,

    /// Prior event digest qb64
    #[serde(default)]
    pub p: String,

    /// Latest event digest qb64
    #[serde(default)]
    pub d: String,

    /// First seen ordinal number of latest event in KEL as hex str
    #[serde(default = "default_sequence_number")]
    pub f: String,

    /// Datetime iso-8601 of key state record update, usually now
    #[serde(default)]
    pub dt: String,

    /// Latest event packet type (ilk)
    #[serde(default)]
    pub et: String,

    /// Signing threshold sith
    #[serde(default = "default_threshold")]
    pub kt: String,

    /// Signing keys qb64
    #[serde(default)]
    pub k: Vec<String>,

    /// Next prerotated threshold sith
    #[serde(default = "default_threshold")]
    pub nt: String,

    /// Pre-rotation keys qb64
    #[serde(default)]
    pub n: Vec<String>,

    /// Backer threshold hex num
    #[serde(default = "default_threshold")]
    pub bt: String,

    /// Backer aids qb64
    #[serde(default)]
    pub b: Vec<String>,

    /// Config traits
    #[serde(default)]
    pub c: Vec<String>,

    /// Establishment event record
    #[serde(default)]
    pub ee: StateEERecord,

    /// Delegator aid qb64 or empty str if not delegated
    #[serde(default)]
    pub di: String,
}

impl Default for StateEERecord {
    fn default() -> Self {
        StateEERecord {
            s: "0".to_string(),
            d: "".to_string(),
            br: None,
            ba: None,
        }
    }
}

impl Default for KeyStateRecord {
    fn default() -> Self {
        KeyStateRecord {
            vn: Vec::new(),
            i: "".to_string(),
            s: "0".to_string(),
            p: "".to_string(),
            d: "".to_string(),
            f: "0".to_string(),
            dt: "".to_string(),
            et: "".to_string(),
            kt: "0".to_string(),
            k: Vec::new(),
            nt: "0".to_string(),
            n: Vec::new(),
            bt: "0".to_string(),
            b: Vec::new(),
            c: Vec::new(),
            ee: StateEERecord::default(),
            di: "".to_string(),
        }
    }
}

/// Helper function to provide default value for sequence numbers
fn default_sequence_number() -> String {
    "0".to_string()
}

/// Helper function to provide default value for thresholds
fn default_threshold() -> String {
    "0".to_string()
}

impl StateEERecord {
    /// Create a new StateEERecord from a StateEstEvent
    pub fn from_state_est_event(event: &StateEstEvent) -> Result<Self, KERIError> {
        Ok(StateEERecord {
            s: event.s.clone(),
            d: event.d.clone(),
            br: event.br.clone(),
            ba: event.ba.clone(),
        })
    }

    /// Convert to a map representation
    pub fn to_map(&self) -> IndexMap<String, SadValue> {
        let mut map = IndexMap::new();
        map.insert("s".to_string(), SadValue::String(self.s.clone()));
        map.insert("d".to_string(), SadValue::String(self.d.clone()));
        map.insert(
            "br".to_string(),
            SadValue::Array(
                self.br
                    .clone()
                    .unwrap()
                    .iter()
                    .map(|s| SadValue::String(s.to_string()))
                    .collect(),
            ),
        );
        map.insert(
            "ba".to_string(),
            SadValue::Array(
                self.ba
                    .clone()
                    .unwrap()
                    .iter()
                    .map(|s| SadValue::String(s.to_string()))
                    .collect(),
            ),
        );

        map
    }

    /// Create from a map representation
    pub fn from_map(map: &IndexMap<String, SadValue>) -> Result<Self, KERIError> {
        let s = match map.get("s") {
            Some(SadValue::String(s)) => s.clone(),
            _ => "0".to_string(),
        };

        let d = match map.get("d") {
            Some(SadValue::String(d)) => d.clone(),
            _ => "".to_string(),
        };

        let br = match map.get("br") {
            Some(SadValue::Array(arr)) => {
                let mut br_vec = Vec::new();
                for item in arr {
                    if let SadValue::String(s) = item {
                        br_vec.push(s.clone());
                    }
                }
                Some(br_vec)
            }
            _ => None,
        };

        let ba = match map.get("ba") {
            Some(SadValue::Array(arr)) => {
                let mut ba_vec = Vec::new();
                for item in arr {
                    if let SadValue::String(s) = item {
                        ba_vec.push(s.clone());
                    }
                }
                Some(ba_vec)
            }
            _ => None,
        };

        Ok(StateEERecord { s, d, br, ba })
    }
}

impl KeyStateRecord {
    /// Convert to a map representation
    pub fn to_map(&self) -> IndexMap<String, SadValue> {
        let mut map = IndexMap::new();
        map.insert(
            "vn".to_string(),
            SadValue::Array(
                self.vn
                    .iter()
                    .map(|n| SadValue::Number(serde_json::Number::from(*n)))
                    .collect(),
            ),
        );
        map.insert("i".to_string(), SadValue::String(self.i.clone()));
        map.insert("s".to_string(), SadValue::String(self.s.clone()));
        map.insert("p".to_string(), SadValue::String(self.p.clone()));
        map.insert("d".to_string(), SadValue::String(self.d.clone()));
        map.insert("f".to_string(), SadValue::String(self.f.clone()));
        map.insert("dt".to_string(), SadValue::String(self.dt.clone()));
        map.insert("et".to_string(), SadValue::String(self.et.clone()));
        map.insert("kt".to_string(), SadValue::String(self.kt.clone()));
        map.insert(
            "k".to_string(),
            SadValue::Array(
                self.k
                    .iter()
                    .map(|s| SadValue::String(s.to_string()))
                    .collect(),
            ),
        );
        map.insert("nt".to_string(), SadValue::String(self.nt.clone()));
        map.insert(
            "n".to_string(),
            SadValue::Array(
                self.n
                    .iter()
                    .map(|s| SadValue::String(s.to_string()))
                    .collect(),
            ),
        );
        map.insert("bt".to_string(), SadValue::String(self.bt.clone()));
        map.insert(
            "b".to_string(),
            SadValue::Array(
                self.b
                    .iter()
                    .map(|s| SadValue::String(s.to_string()))
                    .collect(),
            ),
        );
        map.insert(
            "c".to_string(),
            SadValue::Array(
                self.c
                    .iter()
                    .map(|s| SadValue::String(s.to_string()))
                    .collect(),
            ),
        );
        map.insert("ee".to_string(), SadValue::Object(self.ee.to_map()));
        map.insert("di".to_string(), SadValue::String(self.di.clone()));

        map
    }

    /// Create from a map representation
    pub fn from_map(map: &IndexMap<String, SadValue>) -> Result<Self, KERIError> {
        let vn = match map.get("vn") {
            Some(SadValue::Array(arr)) => {
                let mut vn_vec = Vec::new();
                for item in arr {
                    if let SadValue::Number(n) = item {
                        if let Some(n) = n.as_u64() {
                            vn_vec.push(n as u8);
                        }
                    }
                }
                vn_vec
            }
            _ => Vec::new(),
        };

        let i = match map.get("i") {
            Some(SadValue::String(i)) => i.clone(),
            _ => "".to_string(),
        };

        let s = match map.get("s") {
            Some(SadValue::String(s)) => s.clone(),
            _ => "0".to_string(),
        };

        let p = match map.get("p") {
            Some(SadValue::String(p)) => p.clone(),
            _ => "".to_string(),
        };

        let d = match map.get("d") {
            Some(SadValue::String(d)) => d.clone(),
            _ => "".to_string(),
        };

        let f = match map.get("f") {
            Some(SadValue::String(f)) => f.clone(),
            _ => "0".to_string(),
        };

        let dt = match map.get("dt") {
            Some(SadValue::String(dt)) => dt.clone(),
            _ => "".to_string(),
        };

        let et = match map.get("et") {
            Some(SadValue::String(et)) => et.clone(),
            _ => "".to_string(),
        };

        let kt = match map.get("kt") {
            Some(SadValue::String(kt)) => kt.clone(),
            _ => "0".to_string(),
        };

        let k = match map.get("k") {
            Some(SadValue::Array(arr)) => {
                let mut k_vec = Vec::new();
                for item in arr {
                    if let SadValue::String(s) = item {
                        k_vec.push(s.clone());
                    }
                }
                k_vec
            }
            _ => Vec::new(),
        };

        let nt = match map.get("nt") {
            Some(SadValue::String(nt)) => nt.clone(),
            _ => "0".to_string(),
        };

        let n = match map.get("n") {
            Some(SadValue::Array(arr)) => {
                let mut n_vec = Vec::new();
                for item in arr {
                    if let SadValue::String(s) = item {
                        n_vec.push(s.clone());
                    }
                }
                n_vec
            }
            _ => Vec::new(),
        };

        let bt = match map.get("bt") {
            Some(SadValue::String(bt)) => bt.clone(),
            _ => "0".to_string(),
        };

        let b = match map.get("b") {
            Some(SadValue::Array(arr)) => {
                let mut b_vec = Vec::new();
                for item in arr {
                    if let SadValue::String(s) = item {
                        b_vec.push(s.clone());
                    }
                }
                b_vec
            }
            _ => Vec::new(),
        };

        let c = match map.get("c") {
            Some(SadValue::Array(arr)) => {
                let mut c_vec = Vec::new();
                for item in arr {
                    if let SadValue::String(s) = item {
                        c_vec.push(s.clone());
                    }
                }
                c_vec
            }
            _ => Vec::new(),
        };

        let ee = match map.get("ee") {
            Some(SadValue::Object(obj)) => {
                let ee_map: IndexMap<String, SadValue> =
                    obj.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
                StateEERecord::from_map(&ee_map)?
            }
            _ => StateEERecord::default(),
        };

        let di = match map.get("di") {
            Some(SadValue::String(di)) => di.clone(),
            _ => "".to_string(),
        };

        Ok(KeyStateRecord {
            vn,
            i,
            s,
            p,
            d,
            f,
            dt,
            et,
            kt,
            k,
            nt,
            n,
            bt,
            b,
            c,
            ee,
            di,
        })
    }
}

/// StateEstEvent namedtuple equivalent for latest establishment event
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateEstEvent {
    /// Sequence number of latest est evt lowercase hex no leading zeros
    pub s: String,

    /// SAID qb64 of latest est evt
    pub d: String,

    /// Backer aids qb64 remove list (cuts) from latest est event
    #[serde(default)]
    pub br: Option<Vec<String>>,

    /// Backer aids qb64 add list (adds) from latest est event
    #[serde(default)]
    pub ba: Option<Vec<String>>,
}

impl Default for StateEstEvent {
    fn default() -> Self {
        StateEstEvent {
            s: "0".to_string(),
            d: "".to_string(),
            br: None,
            ba: None,
        }
    }
}
