use serde::{Deserialize, Serialize};

/// Habitat application state information keyed by habitat name (baser.habs)
///
/// Corresponds to HabitatRecord dataclass from keripy

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HabitatRecord {
    /// Habitat own identifier prefix qb64
    #[serde(default)]
    pub hid: String,

    /// Habitat name
    #[serde(default)]
    pub name: Option<String>,

    /// Domain
    #[serde(default)]
    pub domain: Option<String>,

    /// Group member identifier qb64 when hid is group
    #[serde(default)]
    pub mid: Option<String>,

    /// Group signing member identifiers qb64 when hid is group
    #[serde(default)]
    pub smids: Option<Vec<String>>,

    /// Group rotating member identifiers qb64 when hid is group
    #[serde(default)]
    pub rmids: Option<Vec<String>>,

    /// Signify identifier qb64 when hid is Signify
    #[serde(default)]
    pub sid: Option<String>,

    /// List of id prefixes qb64 of watchers
    #[serde(default)]
    pub watchers: Vec<String>,
}

impl Default for HabitatRecord {
    fn default() -> Self {
        HabitatRecord {
            hid: "".to_string(),
            name: None,
            domain: None,
            mid: None,
            smids: None,
            rmids: None,
            sid: None,
            watchers: Vec::new(),
        }
    }
}

impl HabitatRecord {
    /// Create a new HabitatRecord with required hid field
    pub fn new(hid: String) -> Self {
        HabitatRecord {
            hid,
            ..Default::default()
        }
    }

    /// Create a new HabitatRecord with hid and watchers
    pub fn new_with_watchers(hid: String, watchers: Vec<String>) -> Self {
        HabitatRecord {
            hid,
            watchers,
            ..Default::default()
        }
    }
}
