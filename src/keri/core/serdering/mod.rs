use crate::cesr::counting::gen_dex;
use crate::cesr::diger::Diger;
use crate::cesr::number::Number;
use crate::cesr::tholder::Tholder;
use crate::cesr::verfer::Verfer;
use crate::cesr::{dig_dex, get_sizes, mtr_dex, BaseMatter, Versionage, VRSN_1_0};
use crate::{keri, Matter};
use crate::keri::{deversify, smell, versify, Ilk, KERIError, Kinds, Protocolage, Said, Smellage};
use base64::prelude::BASE64_STANDARD;
use base64::Engine;
use keri::Ilks;
use serde::{Deserialize, Serialize};
use serde_json::{self, Value};
use std::collections::HashMap;
use tracing::error;
use std::any::Any;

/// Create a validation schema for the different event types
pub fn build_validation_schema() -> HashMap<Ilk, Vec<&'static str>> {
    let mut schema = HashMap::new();

    // For each ilk, define the required fields (those that must be present)
    schema.insert(Ilk::Icp, vec!["v", "t", "d", "i", "s", "kt", "k", "nt", "n", "bt", "b", "c"]);
    schema.insert(Ilk::Rot, vec!["v", "t", "d", "i", "s", "p", "kt", "k", "nt", "n", "bt", "br", "ba"]);
    schema.insert(Ilk::Ixn, vec!["v", "t", "d", "i", "s", "p"]);
    schema.insert(Ilk::Dip, vec!["v", "t", "d", "i", "s", "kt", "k", "nt", "n", "bt", "b", "c", "di"]);
    schema.insert(Ilk::Drt, vec!["v", "t", "d", "i", "s", "p", "kt", "k", "nt", "n", "bt", "br", "ba"]);
    schema.insert(Ilk::Rct, vec!["v", "t", "d", "i", "s"]);
    schema.insert(Ilk::Qry, vec!["v", "t", "d", "dt", "r", "rr", "q"]);
    schema.insert(Ilk::Rpy, vec!["v", "t", "d", "dt", "r", "a"]);
    schema.insert(Ilk::Pro, vec!["v", "t", "d", "dt", "r", "rr", "q"]);
    schema.insert(Ilk::Bar, vec!["v", "t", "d", "dt", "r", "a"]);
    schema.insert(Ilk::Exn, vec!["v", "t", "d", "i", "rp", "p", "dt", "r", "q", "a", "e"]);
    schema.insert(Ilk::Vcp, vec!["v", "t", "d", "i", "ii", "s", "c", "bt", "b", "n"]);
    schema.insert(Ilk::Vrt, vec!["v", "t", "d", "i", "p", "s", "bt", "br", "ba"]);
    schema.insert(Ilk::Iss, vec!["v", "t", "d", "i", "s", "ri", "dt"]);
    schema.insert(Ilk::Rev, vec!["v", "t", "d", "i", "s", "ri", "p", "dt"]);
    schema.insert(Ilk::Bis, vec!["v", "t", "d", "i", "ii", "s", "ra", "dt"]);
    schema.insert(Ilk::Brv, vec!["v", "t", "d", "i", "s", "p", "ra", "dt"]);

    schema
}

/// Get the span length for a given version and serialization format
fn get_version_span(vrsn: &Versionage, kind: &Kinds) -> Result<usize, KERIError> {
    // Define version spans based on serialization kind
    match (vrsn, kind) {
        // KERI protocol version spans
        (Versionage { major: 1, minor: 0 }, Kinds::Json) => Ok(17),
        (Versionage { major: 1, minor: 0 }, Kinds::Cbor) => Ok(17),
        (Versionage { major: 1, minor: 0 }, Kinds::Mgpk) => Ok(17),
        (Versionage { major: 2, minor: 0 }, Kinds::Json) => Ok(16),
        (Versionage { major: 2, minor: 0 }, Kinds::Cbor) => Ok(16),
        (Versionage { major: 2, minor: 0 }, Kinds::Mgpk) => Ok(16),

        // ACDC protocol version spans
        // (Versionage { major: 1, minor: 0 }, _) if vrsn.kind == "ACDC" => Ok(17),
        // Add other version spans as needed

        // Unknown version/kind combination
        _ => Err(KERIError::VersionError("Unsupported version and kind combination".to_string())),
    }
}


#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
enum AttribField {
    StringList(Vec<String>),
    StringMap(HashMap<String, String>),
}


/// A comprehensive struct containing all possible KERI event fields
/// with Option<T> for fields that aren't required by all event types
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Sadder {
    /// Version string - required in all events
    pub v: String,

    /// Type/ilk identifier (e.g., "icp", "rot", "ixn", etc.) - required in all events
    pub t: String,

    /// Self-addressing identifier (digest) - required in all events
    pub d: String,

    /// Identifier - required in most events
    #[serde(skip_serializing_if = "Option::is_none")]
    pub i: Option<String>,

    /// Identifier - required in most events
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rp: Option<String>,

    /// Sequence number - required in most events
    #[serde(skip_serializing_if = "Option::is_none")]
    pub s: Option<String>,

    /// Previous digest - used in rotation events
    #[serde(skip_serializing_if = "Option::is_none")]
    pub p: Option<String>,

    /// Key threshold - used in key management events
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kt: Option<String>,

    /// Keys - used in key management events
    #[serde(skip_serializing_if = "Option::is_none")]
    pub k: Option<Vec<String>>,

    /// Next key threshold - used in key management events
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nt: Option<String>,

    /// Next keys - used in key management events
    #[serde(skip_serializing_if = "Option::is_none")]
    pub n: Option<Vec<String>>,

    /// Backer threshold - inception and some other events
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bt: Option<String>,

    /// Backers - inception and some other events
    #[serde(skip_serializing_if = "Option::is_none")]
    pub b: Option<Vec<String>>,

    /// Uuid - Properties for vcp  (registry  inception event)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub u: Option<String>,

    /// Configuration traits - inception events
    #[serde(skip_serializing_if = "Option::is_none")]
    pub c: Option<Vec<String>>,

    /// Anchors or additional data - various events
    #[serde(skip_serializing_if = "Option::is_none")]
    pub a: Option<AttribField>,

    /// Anchors or additional data - various events
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "A")]
    pub cap_a: Option<Vec<String>>,

    /// Route - used in query/reply events
    #[serde(skip_serializing_if = "Option::is_none")]
    pub r: Option<String>,

    /// Route - used in query/reply events
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rr: Option<String>,

    /// Query parameters - used in query events
    #[serde(skip_serializing_if = "Option::is_none")]
    pub q: Option<Value>,

    /// Delegator identifier - used in delegation events (DIP, DRT)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub di: Option<String>,

    /// Timestamp - used in various events
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dt: Option<String>,

    /// Registry identifier - used in registry events
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ri: Option<String>,

    /// Seals - used in various events
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seal: Option<Vec<Value>>,

    /// Receipt - used in receipt events (RCT)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rct: Option<Value>,

    /// Witness receipts - used in witness events
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wr: Option<Vec<Value>>,

    /// Witness removal - rotation events
    #[serde(skip_serializing_if = "Option::is_none")]
    pub br: Option<Vec<String>>,

    /// Witness add - rotation events
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ba: Option<Value>,

    /// Credential issuance data - used in credential events (ISS, REV)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ii: Option<String>,

    /// Schema reference - used in schema and credential events
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sr: Option<String>,

    /// Rule data - used for rule events
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rules: Option<Value>,

    /// Edge data - used for graph/edge events
    #[serde(skip_serializing_if = "Option::is_none")]
    pub e: Option<Value>,

    /// Aggregate data - used for aggregate events
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ag: Option<Value>,

    /// Attachments for credentials or other data
    #[serde(skip_serializing_if = "Option::is_none")]
    pub at: Option<Vec<Value>>,
}

impl Sadder {
    /// Creates a new basic KeriEvent with mandatory fields
    pub fn new(version: String, ilk: String, digest: String) -> Self {
        Self {
            v: version,
            t: ilk,
            d: digest,
            ..Default::default()
        }
    }

    /// Creates a Sadder with type-specific field defaults based on an existing Sadder
    ///
    /// # Arguments
    /// * `orig` - The original Sadder object to preserve values from
    ///
    /// # Returns
    /// A new Sadder instance with appropriate defaults for the given ilk,
    /// preserving any existing values from the original
    pub fn default_with_type(ilk: Ilk, orig: &Sadder) -> Self {
        let mut sad = Self::default();
        let ilk = if orig.t.is_empty() { ilk.as_str().to_string() } else { orig.t.clone() };

        // Preserve version if already set
        sad.v = if orig.v.is_empty() { "".to_string() } else { orig.v.clone() };
        // Set the type from original
        sad.t = ilk.clone();
        // Preserve digest if already set
        sad.d = if orig.d.is_empty() { "".to_string() } else { orig.d.clone() };

        // Apply type-specific defaults based on ilk
        match ilk.as_str() {
            "icp" => {
                sad.s = orig.s.clone().or(Some("0".to_string()));
                sad.kt = orig.kt.clone().or(Some("0".to_string()));
                sad.k = orig.k.clone().or(Some(vec![]));
                sad.nt = orig.nt.clone().or(Some("0".to_string()));
                sad.n = orig.n.clone().or(Some(vec![]));
                sad.bt = orig.bt.clone().or(Some("0".to_string()));
                sad.b = orig.b.clone().or(Some(vec![]));
                sad.c = orig.c.clone().or(Some(vec![]));
                sad.a = orig.a.clone().or_else(|| Some(AttribField::StringList(vec![])));
                sad.i = orig.i.clone().or(Some("".to_string()));
            },
            "rot" => {
                sad.s = orig.s.clone().or(Some("0".to_string()));
                sad.p = orig.p.clone().or(Some("".to_string()));
                sad.kt = orig.kt.clone().or(Some("0".to_string()));
                sad.k = orig.k.clone().or(Some(vec![]));
                sad.nt = orig.nt.clone().or(Some("0".to_string()));
                sad.n = orig.n.clone().or(Some(vec![]));
                sad.bt = orig.bt.clone().or(Some("0".to_string()));
                sad.br = orig.br.clone().or(Some(vec![]));
                sad.ba = orig.ba.clone().or(Some(Value::Array(vec![])));
                sad.a = orig.a.clone().or_else(|| Some(AttribField::StringList(vec![])));
                sad.i = orig.i.clone().or(Some("".to_string()));
            },
            "ixn" => {
                sad.s = orig.s.clone().or(Some("0".to_string()));
                sad.p = orig.p.clone().or(Some("".to_string()));
                sad.a = orig.a.clone().or_else(|| Some(AttribField::StringList(vec![])));
                sad.i = orig.i.clone().or(Some("".to_string()));
            },
            "dip" => {
                sad.s = orig.s.clone().or(Some("0".to_string()));
                sad.kt = orig.kt.clone().or(Some("0".to_string()));
                sad.k = orig.k.clone().or(Some(vec![]));
                sad.nt = orig.nt.clone().or(Some("0".to_string()));
                sad.n = orig.n.clone().or(Some(vec![]));
                sad.bt = orig.bt.clone().or(Some("0".to_string()));
                sad.b = orig.b.clone().or(Some(vec![]));
                sad.c = orig.c.clone().or(Some(vec![]));
                sad.a = orig.a.clone().or_else(|| Some(AttribField::StringList(vec![])));
                sad.di = orig.di.clone().or(Some("".to_string()));
                sad.i = orig.i.clone().or(Some("".to_string()));
            },
            "drt" => {
                sad.s = orig.s.clone().or(Some("0".to_string()));
                sad.p = orig.p.clone().or(Some("".to_string()));
                sad.kt = orig.kt.clone().or(Some("0".to_string()));
                sad.k = orig.k.clone().or(Some(vec![]));
                sad.nt = orig.nt.clone().or(Some("0".to_string()));
                sad.n = orig.n.clone().or(Some(vec![]));
                sad.bt = orig.bt.clone().or(Some("0".to_string()));
                sad.br = orig.br.clone().or(Some(vec![]));
                sad.ba = orig.ba.clone().or(Some(Value::Array(vec![])));
                sad.a = orig.a.clone().or_else(|| Some(AttribField::StringList(vec![])));
                sad.i = orig.i.clone().or(Some("".to_string()));
            },
            "rct" => {
                sad.s = orig.s.clone().or(Some("0".to_string()));
                sad.i = orig.i.clone().or(Some("".to_string()));
            },
            "qry" => {
                sad.dt = orig.dt.clone().or(Some("".to_string()));
                sad.r = orig.r.clone().or(Some("".to_string()));
                sad.rr = orig.rr.clone().or(Some("".to_string()));
                sad.q = orig.q.clone().or_else(|| Some(Value::Object(serde_json::Map::new())));
            },
            "rpy" => {
                sad.dt = orig.dt.clone().or(Some("".to_string()));
                sad.r = orig.r.clone().or(Some("".to_string()));
                sad.a = orig.a.clone().or_else(|| Some(AttribField::StringList(vec![])));
            },
            "pro" => {
                sad.dt = orig.dt.clone().or(Some("".to_string()));
                sad.r = orig.r.clone().or(Some("".to_string()));
                sad.rr = orig.rr.clone().or(Some("".to_string()));
                sad.q = orig.q.clone().or_else(|| Some(Value::Object(serde_json::Map::new())));
            },
            "bar" => {
                sad.dt = orig.dt.clone().or(Some("".to_string()));
                sad.r = orig.r.clone().or(Some("".to_string()));
                sad.a = orig.a.clone().or_else(|| Some(AttribField::StringList(vec![])));
            },
            "exn" => {
                sad.i = orig.i.clone().or(Some("".to_string()));
                sad.rp = orig.rp.clone().or(Some("".to_string()));
                sad.p = orig.p.clone().or(Some("".to_string()));
                sad.dt = orig.dt.clone().or(Some("".to_string()));
                sad.r = orig.r.clone().or(Some("".to_string()));
                sad.q = orig.q.clone().or_else(|| Some(Value::Object(serde_json::Map::new())));
                sad.a = orig.a.clone().or_else(|| Some(AttribField::StringList(vec![])));
                sad.e = orig.e.clone().or_else(|| Some(Value::Object(serde_json::Map::new())));
            },
            "vcp" => {
                sad.i = orig.i.clone().or(Some("".to_string()));
                sad.ii = orig.ii.clone().or(Some("".to_string()));
                sad.s = orig.s.clone().or(Some("0".to_string()));
                sad.c = orig.c.clone().or(Some(vec![]));
                sad.bt = orig.bt.clone().or(Some("0".to_string()));
                sad.b = orig.b.clone().or(Some(vec![]));
            },
            "vrt" => {
                sad.i = orig.i.clone().or(Some("".to_string()));
                sad.p = orig.p.clone().or(Some("".to_string()));
                sad.s = orig.s.clone().or(Some("0".to_string()));
                sad.bt = orig.bt.clone().or(Some("0".to_string()));
                sad.br = orig.br.clone().or(Some(vec![]));
                sad.ba = orig.ba.clone().or(Some(Value::Array(vec![])));
            },
            "iss" => {
                sad.i = orig.i.clone().or(Some("".to_string()));
                sad.s = orig.s.clone().or(Some("0".to_string()));
                sad.ri = orig.ri.clone().or(Some("".to_string()));
                sad.dt = orig.dt.clone().or(Some("".to_string()));
            },
            "rev" => {
                sad.i = orig.i.clone().or(Some("".to_string()));
                sad.s = orig.s.clone().or(Some("0".to_string()));
                sad.ri = orig.ri.clone().or(Some("".to_string()));
                sad.p = orig.p.clone().or(Some("".to_string()));
                sad.dt = orig.dt.clone().or(Some("".to_string()));
            },
            "bis" => {
                sad.i = orig.i.clone().or(Some("".to_string()));
                sad.ii = orig.ii.clone().or(Some("".to_string()));
                sad.s = orig.s.clone().or(Some("0".to_string()));
                sad.rules = orig.rules.clone().or_else(|| Some(Value::Object(serde_json::Map::new())));
                sad.dt = orig.dt.clone().or(Some("".to_string()));
            },
            "brv" => {
                sad.i = orig.i.clone().or(Some("".to_string()));
                sad.s = orig.s.clone().or(Some("0".to_string()));
                sad.p = orig.p.clone().or(Some("".to_string()));
                sad.rules = orig.rules.clone().or_else(|| Some(Value::Object(serde_json::Map::new())));
                sad.dt = orig.dt.clone().or(Some("".to_string()));
            },
            // Default case for unknown ilk types
            _ => {
                // Keep the base defaults from Self::default()
            }
        }

        sad
    }

    /// Sets the SAID fields with dummy placeholders of the appropriate length
    ///
    /// # Arguments
    /// * `saids` - Optional map of label to digest type code overrides
    ///
    /// This function sets the digestive fields with proper length placeholders
    /// based on the digest type
    pub fn set_said_placeholders(&mut self, saids: Option<HashMap<&str, String>>) {
        // Define the default SAIDs mapping
        let mut _saids: HashMap<&str, String> = HashMap::new();

        // Set up the defaults based on the ilk type
        match self.t.as_str() {
            "icp" | "dip" => {
                _saids.insert("d", mtr_dex::BLAKE3_256.to_string()); // Blake3_256
                if !self.i.clone().unwrap().is_empty() {
                    match BaseMatter::from_qb64(&self.i.clone().unwrap()) {
                        Ok(mtr) => {
                            let code = String::from(mtr.code().clone());
                            if dig_dex::TUPLE.contains(&code.as_str()) {
                                _saids.insert("i", code);
                            }
                        }
                        Err(_) => {
                            _saids.insert("i", mtr_dex::BLAKE3_256.to_string()); // Blake3_256
                        }
                    }
                } else {
                    _saids.insert("i", mtr_dex::BLAKE3_256.to_string()); // Blake3_256
                }
            },
            "rot" | "drt" | "vrt" | "rev" | "brv" => {
                _saids.insert("d", mtr_dex::BLAKE3_256.to_string()); // Blake3_256
            },
            "ixn" | "rct" => {
                _saids.insert("d", mtr_dex::BLAKE3_256.to_string()); // Blake3_256
            },
            "qry" | "rpy" | "pro" | "bar" | "exn" => {
                _saids.insert("d", mtr_dex::BLAKE3_256.to_string()); // Blake3_256
            },
            "vcp" => {
                _saids.insert("d", mtr_dex::BLAKE3_256.to_string()); // Blake3_256
                _saids.insert("i", mtr_dex::BLAKE3_256.to_string()); // Blake3_256
            },
            "iss" => {
                _saids.insert("d", mtr_dex::BLAKE3_256.to_string()); // Blake3_256
            },
            "bis" => {
                _saids.insert("d", mtr_dex::BLAKE3_256.to_string()); // Blake3_256
            },
            _ => {} // No defaults for unknown types
        }

        // Dummy character for padding
        let dummy = "#";

        // Field sizes for different digest types (fs = full size in characters)
        let sizes = get_sizes();

        // Process each SAID field
        for (label, code) in _saids.iter() {
            // Check for override in provided saids
            let code = if let Some(saids_map) = &saids {
                saids_map.get(label).unwrap_or(code)
            } else {
                code
            };

            // Check if this is a digestive code that needs padding
            if let Some(size) = sizes.get(code.as_str()) {
                let fs = size.fs.unwrap();
                // Create a properly sized dummy string
                let dummy_value = dummy.repeat(fs as usize);

                // Set the appropriate field based on the label
                match *label {
                    "d" => self.d = dummy_value,
                    "i" => if let Some(i) = &mut self.i {
                        *i = dummy_value;
                    } else {
                        self.i = Some(dummy_value);
                    },
                    // Add other SAID fields as needed
                    _ => {} // Ignore unknown labels
                }
            }
        }
    }


    /// Creates a specific event type from this general structure
    pub fn ilk(&self) -> Result<Ilk, KERIError> {
        match self.t.as_str() {
            Ilks::ICP => Ok(Ilk::Icp),
            Ilks::ROT => Ok(Ilk::Rot),
            Ilks::IXN => Ok(Ilk::Ixn),
            Ilks::DIP => Ok(Ilk::Dip),
            Ilks::DRT => Ok(Ilk::Drt),
            Ilks::RCT => Ok(Ilk::Rct),
            Ilks::QRY => Ok(Ilk::Qry),
            Ilks::RPY => Ok(Ilk::Rpy),
            Ilks::VCP => Ok(Ilk::Vcp),
            Ilks::VRT => Ok(Ilk::Vrt),
            Ilks::ISS => Ok(Ilk::Iss),
            Ilks::REV => Ok(Ilk::Rev),
            _ => Err(KERIError::FieldError(String::from("Unknown event type"))),
        }
    }

    /// Determine if this event is a key state establishment event
    pub fn is_establishment_event(&self) -> bool {
        matches!(
            self.t.as_str(),
            Ilks::ICP | Ilks::ROT | Ilks::DIP | Ilks::DRT | Ilks::VCP | Ilks::VRT | Ilks::RIP
        )
    }

    fn get_primary_said_label(&self) -> Option<Said> {
        match &self.ilk() {
            Ok(ilk) => match ilk {
                Ilk::Icp => Some(Said::D),
                Ilk::Rot => Some(Said::D),
                Ilk::Ixn => Some(Said::D),
                Ilk::Dip => Some(Said::D),
                Ilk::Drt => Some(Said::D),
                Ilk::Qry => Some(Said::D),
                Ilk::Rpy => Some(Said::D),
                Ilk::Pro => Some(Said::D),
                Ilk::Bar => Some(Said::D),
                Ilk::Exn => Some(Said::D),
                Ilk::Vcp => Some(Said::D),
                Ilk::Vrt => Some(Said::D),
                Ilk::Iss => Some(Said::D),
                Ilk::Rev => Some(Said::D),
                Ilk::Bis => Some(Said::D),
                Ilk::Brv => Some(Said::D),
                _ => None,
            },
            _ => None,
        }
    }

    /// Validate the Sadder instance based on its ilk (event type)
    pub fn validate(&self) -> Result<(), KERIError> {
        // Get the ilk from the t field
        let ilk = Ilk::from_str(&self.t)
            .ok_or_else(|| KERIError::UnknownIlk(self.t.clone()))?;

        // Get the validation schema
        let validation_schema = build_validation_schema();

        // Get the required fields for this ilk
        let required_fields = validation_schema.get(&ilk)
            .expect("All ilks should have validation rules");

        // Check each required field
        for &field in required_fields {
            match field {
                "v" => if self.v.is_empty() {
                    return Err(KERIError::MissingRequiredField("v".to_string(), self.t.clone()));
                },
                "t" => if self.t.is_empty() {
                    return Err(KERIError::MissingRequiredField("t".to_string(), self.t.clone()));
                },
                "d" => if self.d.is_empty() {
                    return Err(KERIError::MissingRequiredField("d".to_string(), self.t.clone()));
                },
                "i" => if self.i.is_none() {
                    return Err(KERIError::MissingRequiredField("i".to_string(), self.t.clone()));
                },
                "s" => if self.s.is_none() {
                    return Err(KERIError::MissingRequiredField("s".to_string(), self.t.clone()));
                },
                "p" => if self.p.is_none() {
                    return Err(KERIError::MissingRequiredField("p".to_string(), self.t.clone()));
                },
                "kt" => if self.kt.is_none() {
                    return Err(KERIError::MissingRequiredField("kt".to_string(), self.t.clone()));
                },
                "k" => if self.k.is_none() {
                    return Err(KERIError::MissingRequiredField("k".to_string(), self.t.clone()));
                },
                "nt" => if self.nt.is_none() {
                    return Err(KERIError::MissingRequiredField("nt".to_string(), self.t.clone()));
                },
                "n" => if self.n.is_none() {
                    return Err(KERIError::MissingRequiredField("n".to_string(), self.t.clone()));
                },
                "bt" => if self.bt.is_none() {
                    return Err(KERIError::MissingRequiredField("bt".to_string(), self.t.clone()));
                },
                "b" => if self.b.is_none() {
                    return Err(KERIError::MissingRequiredField("b".to_string(), self.t.clone()));
                },
                "c" => if self.c.is_none() {
                    return Err(KERIError::MissingRequiredField("c".to_string(), self.t.clone()));
                },
                "a" => if self.a.is_none() {
                    return Err(KERIError::MissingRequiredField("a".to_string(), self.t.clone()));
                },
                "di" => if self.di.is_none() {
                    return Err(KERIError::MissingRequiredField("di".to_string(), self.t.clone()));
                },
                "dt" => if self.dt.is_none() {
                    return Err(KERIError::MissingRequiredField("dt".to_string(), self.t.clone()));
                },
                "r" => if self.r.is_none() {
                    return Err(KERIError::MissingRequiredField("r".to_string(), self.t.clone()));
                },
                "rr" => {
                    // Not directly in the Sadder struct, needs special handling
                    // Since rr isn't directly in the struct, this would need custom validation
                    // or would need to check a specific field in q if rr is contained there
                },
                "q" => if self.q.is_none() {
                    return Err(KERIError::MissingRequiredField("q".to_string(), self.t.clone()));
                },
                "ri" => if self.ri.is_none() {
                    return Err(KERIError::MissingRequiredField("ri".to_string(), self.t.clone()));
                },
                "br" => if self.br.is_none() {
                    return Err(KERIError::MissingRequiredField("br".to_string(), self.t.clone()));
                },
                "ba" => if self.ba.is_none() {
                    return Err(KERIError::MissingRequiredField("ba".to_string(), self.t.clone()));
                },
                "ii" => if self.ii.is_none() {
                    return Err(KERIError::MissingRequiredField("ii".to_string(), self.t.clone()));
                },
                "rp" => {
                    // Not directly in the Sadder struct, needs special handling
                    // Since rp isn't directly in the struct, this would need custom validation
                },
                "e" => if self.e.is_none() {
                    return Err(KERIError::MissingRequiredField("e".to_string(), self.t.clone()));
                },
                "ra" => {
                    // Not directly in the Sadder struct, needs special handling
                    // This could be part of another field or requires custom validation
                },
                _ => {}
            }
        }

        Ok(())
    }

    /// Helper method for more detailed validation with custom messages
    pub fn is_valid(&self) -> Result<(), String> {
        match self.validate() {
            Ok(()) => Ok(()),
            Err(err) => Err(format!("Validation error: {}", err)),
        }
    }

}


// Extension to validate a specific field to allow more modular validation
pub trait FieldValidator {
    fn validate_field(&self, field: &str) -> bool;
}

impl FieldValidator for Sadder {
    fn validate_field(&self, field: &str) -> bool {
        match field {
            "v" => !self.v.is_empty(),
            "t" => !self.t.is_empty(),
            "d" => !self.d.is_empty(),
            "i" => self.i.is_some(),
            "s" => self.s.is_some(),
            "p" => self.p.is_some(),
            "kt" => self.kt.is_some(),
            "k" => self.k.is_some(),
            "nt" => self.nt.is_some(),
            "n" => self.n.is_some(),
            "bt" => self.bt.is_some(),
            "b" => self.b.is_some(),
            "c" => self.c.is_some(),
            "a" => self.a.is_some(),
            "A" => self.cap_a.is_some(),
            "di" => self.di.is_some(),
            "dt" => self.dt.is_some(),
            "r" => self.r.is_some(),
            "q" => self.q.is_some(),
            "ri" => self.ri.is_some(),
            "br" => self.br.is_some(),
            "ba" => self.ba.is_some(),
            "ii" => self.ii.is_some(),
            "e" => self.e.is_some(),
            _ => false,
        }
    }
}


/// Base implementation of the Serder trait for serializable/deserializable entities
#[derive(Debug, Clone)]
pub struct BaseSerder {
    /// Serialized message as bytes
    raw: Vec<u8>,
    /// Serializable attribute dictionary (key event dict)
    sad: Sadder,
    /// Protocol identifier type (e.g., 'KERI' or 'ACDC')
    proto: String,
    /// Event version information
    vrsn: Versionage,
    /// Serialization kind (json, cbor, msgpack, binary)
    kind: Kinds,
    /// Number of bytes in serialized event
    size: usize,
    /// qb64 self-addressing identifier given by appropriate saidive field
    said: Option<String>,
    /// CESR genus code for this Serder
    genus: String,
    /// CESR genus code table version for this Serder
    gvrsn: Versionage,
}


impl Default for BaseSerder {
    fn default() -> Self {
        BaseSerder {
            raw: Vec::new(),
            sad: Sadder::default(),
            proto: String::new(),
            vrsn: Versionage { major: 1, minor: 0 },
            kind: Kinds::Json,
            size: 0,
            said: None,
            genus: String::new(),
            gvrsn: Versionage { major: 1, minor: 0 },
        }
    }
}

impl BaseSerder {

    pub fn from_init(raw: Option<&[u8]>, sad: Option<&Sadder>, makify: Option<bool>,
                         smellage: Option<Smellage>, proto: Option<String>, vrsn: Option<Versionage>,
                         kind: Option<Kinds>, ilk: Option<Ilk>,
                     saids: Option<HashMap<&str, String>>) -> Result<Self, KERIError> {
        let mfy = makify.unwrap_or(true);

        match raw {
            Some(raw) => {
                Self::from_raw(raw, smellage)
            }
            None => {
                if mfy {
                    let mut serder = Self::default();
                    serder.makify(sad.unwrap_or(&Sadder::default()), proto, vrsn, kind, ilk, saids)?;
                    Ok(serder)
                } else {
                    match sad {
                        Some(sad) => {
                            Self::from_sad(sad)
                        }
                        None => {
                            Err(KERIError::MissingRequiredField("raw".to_string(), "Raw or Sad required".to_string()))?
                        }
                    }
                }
            }
        }
    }

    /// Returns an error if verification fails or if required fields are missing
    pub fn from_raw(raw: &[u8], smellage: Option<Smellage>) -> Result<Self, KERIError> {
        // Create a new BaseSerder instance
        // Inhale the raw data (equivalent to _inhale in Python)
        // Parse smellage or smell the raw data
        let genus = gen_dex::KERI.to_string();
        let (proto, vrsn, kind, size, gvrsn) = match smellage {
            Some(smell) => {
                // Use provided smellage
                (smell.proto, smell.vrsn, smell.kind, smell.size, smell.gvrsn)
            }
            None => {
                // Smell the raw data
                let smell = smell(raw)?;
                (smell.proto, smell.vrsn, smell.kind, smell.size, smell.gvrsn)
            }
        };

        // Deserialize data based on kind
        let sad = BaseSerder::loads(raw, Some(size), Kinds::from(&kind)?)?;
        let said_label = sad.get_primary_said_label();

        // Verify version field exists
        let mut serder = BaseSerder {
            raw: raw[..size].to_vec(),
            sad,
            proto,
            vrsn,
            kind: Kinds::from(&kind)?,
            size,
            said: None,
            genus,
            gvrsn: gvrsn.unwrap(),
        };

        // Get the primary said field label

        let label = match said_label {
            Some(label) => label,
            None => {
                // Set said to None (null in Python)
                serder.said = None;
                return Ok(serder);
            }
        };

        // Check if the primary said field exists in the sad
        let sad = &serder.sad;
        match label {
            Said::D => {
                serder.said = Some(sad.d.to_string());
            }
            _ => {
                return Err(KERIError::FieldError(format!(
                    "Missing primary said field in {:?}.",
                    sad
                )));                }
        }

        // Note: In Rust, we don't modify the passed-in raw buffer directly
        // The strip functionality would be implemented elsewhere if needed

        // Verify fields including the saids provided in raw
        match serder.verify() {
            Ok(_) => Ok(serder),
            Err(err) => {
                // Log the error
                error!("Invalid raw for Serder {}\n{}", serder.pretty(None), err);

                Err(KERIError::ValidationError(format!(
                    "Invalid raw for Serder = {:?}. {}",
                    serder.sad, err
                )))
            }
        }
    }

    pub fn from_sad(sad: &Sadder) -> Result<Self, KERIError> {
        let genus = String::from(gen_dex::KERI);
        let ver = sad.v.clone();

        let smell = deversify(ver)?;
        let (proto, vrsn, kind, size, gvrsn) =
            (smell.proto, smell.vrsn, smell.kind, smell.size, smell.gvrsn);
        // Verify version field exists

        let raw = BaseSerder::dumps(sad, &Kinds::from(kind.as_str())?)?;

        let mut serder = BaseSerder {
            raw: raw[..size].to_vec(),
            sad: sad.clone(),
            proto,
            vrsn,
            kind: Kinds::from(&kind)?,
            size,
            said: None,
            genus,
            gvrsn: gvrsn.ok_or_else(|| KERIError::FieldError("Missing required gvrsn value".to_string()))?
            ,
        };

        // Get the primary said field label
        let label = match sad.get_primary_said_label() {
            Some(label) => label,
            None => {
                // Set said to None (null in Python)
                serder.said = None;
                return Ok(serder);
            }
        };

        // Check if the primary said field exists in the sad
        // Check if the primary said field exists in the sad
        let sad = &serder.sad;
        match label {
            Said::D => {
                serder.said = Some(sad.d.to_string());
            }
            _ => {
                return Err(KERIError::FieldError(format!(
                    "Missing primary said field in {:?}.",
                    sad
                )));                }
        }

        // Note: In Rust, we don't modify the passed-in raw buffer directly
        // The strip functionality would be implemented elsewhere if needed

        // Verify fields including the saids provided in raw
        match serder.verify() {
            Ok(_) => Ok(serder),
            Err(err) => {
                // Log the error
                error!("Invalid raw for Serder {}\n{}", serder.pretty(None), err);

                Err(KERIError::ValidationError(format!(
                    "Invalid raw for Serder = {:?}. {}",
                    serder.sad, err
                )))
            }
        }
    }

    /// Prepares a Sadder by padding the version field and then calculating the correct version string
    /// This mirrors the Python makify method's versification logic
    ///
    /// # Arguments
    /// * `sad` - The Sadder to prepare
    /// * `kind` - The serialization format kind
    /// * `proto` - The protocol string
    /// * `vrsn` - The version information
    ///
    /// # Returns
    /// The updated Sadder with proper version string
    pub fn prepare_version(&self, sad: &mut Sadder, kind: Kinds, proto: String, vrsn: Versionage) -> Result<(), KERIError> {
        // Only process for these serialization formats
        if matches!(kind, Kinds::Json | Kinds::Cbor | Kinds::Mgpk) {
            // Dummy character for padding
            let dummy = "#";

            // Get the span length for this version
            let span = get_version_span(&vrsn, &kind)?;

            // Pad the version field with dummy characters to ensure proper span
            sad.v = dummy.repeat(span);

            // Serialize to calculate the size
            let raw = Self::dumps(&sad, &kind)?;
            let size = raw.len();

            // Generate the correct version string with the calculated size
            let vs = versify(proto.as_str(), &vrsn, kind.to_string().as_str(), size as u64)?;

            // Update the version string in the Sadder
            sad.v = vs;
        }

        Ok(())
    }

    /// Computes the self-addressing identifier (SAID) for the given raw data and genus.
    ///
    /// # Arguments
    ///
    /// * `raw` - Byte slice of the serialized message.
    /// * `genus` - The CESR genus code associated with the event.
    ///
    /// # Returns
    ///
    /// * `Result<String, KERIError>` - The computed SAID as a base64-encoded string on success,
    ///                                   or a KERIError on failure.
    fn compute_said(raw: &[u8], genus: &str) -> Result<String, KERIError> {
        // Use the appropriate hashing algorithm based on the genus code.
        let hash = match genus {
            "BLAKE3" => blake3::hash(raw).to_hex().to_string(),
            "SHA256" => {
                use sha2::{Digest, Sha256};
                let mut hasher = Sha256::new();
                hasher.update(raw);
                BASE64_STANDARD.encode(hasher.finalize())
            }
            "SHA3_256" => {
                use sha3::{Digest, Sha3_256};
                let mut hasher = Sha3_256::new();
                hasher.update(raw);
                BASE64_STANDARD.encode(hasher.finalize())
            }
            _ => {
                return Err(KERIError::FieldError(format!(
                    "Unsupported genus code for SAID computation: {}",
                    genus
                )));
            }
        };

        Ok(hash)
    }

    // Helper method to get the primary said field label
    fn get_primary_said_label(&self) -> Option<Said> {
        self.sad.get_primary_said_label()
    }

    /// Deserializes raw bytes into a data structure based on the specified kind
    ///
    /// # Arguments
    ///
    /// * `raw` - Raw bytes to deserialize
    /// * `size` - Number of bytes to consume for deserialization (if None, uses all bytes)
    /// * `kind` - Serialization format (JSON, MGPK, CBOR)
    ///
    /// # Returns
    ///
    /// A Result containing either the deserialized data or a KERIError
    ///
    /// # Notes
    ///
    /// JSON deserialization uses UTF-8 string conversion, while CBOR and MGPK operate directly on bytes
    pub fn loads(raw: &[u8], size: Option<usize>, kind: Kinds) -> Result<Sadder, KERIError> {
        // Determine how many bytes to use
        let limit = size.unwrap_or(raw.len());
        let data = &raw[..std::cmp::min(limit, raw.len())];

        match kind {
            Kinds::Json => {
                // Convert bytes to UTF-8 string for JSON
                match std::str::from_utf8(data) {
                    Ok(text) => {
                        let sadder = serde_json::from_str(text)
                            .map_err(|e| KERIError::JsonError(e.to_string()))?;
                        Ok(sadder)
                    }
                    Err(e) => Err(KERIError::JsonError(format!(
                        "Invalid UTF-8 sequence: {}",
                        e
                    ))),
                }
            }

            Kinds::Mgpk => {
                // For msgpack, direct deserialization from bytes
                // In a real implementation, you would use the rmp_serde crate
                // This is a placeholder that simulates the error handling pattern
                Err(KERIError::MgpkError(
                    "MGPK deserialization not implemented".to_string(),
                ))

                // A real implementation might look like:
                // rmp_serde::from_slice(data)
                //     .map_err(|e| KERIError::MgpkError(
                //         format!("{}: {:?}", e, data)
                //     ))
            }

            Kinds::Cbor => {
                // For CBOR, direct deserialization from bytes
                // In a real implementation, you would use the ciborium crate
                // This is a placeholder that simulates the error handling pattern
                Err(KERIError::CborError(
                    "CBOR deserialization not implemented".to_string(),
                ))

                // A real implementation might look like:
                // let mut deserializer = ciborium::de::Deserializer::from_reader(data);
                // let value = serde::de::Deserialize::deserialize(&mut deserializer)
                //     .map_err(|e| KERIError::CborError(
                //         format!("{}: {:?}", e, data)
                //     ));
                // value
            }
            Kinds::Cesr => {
                Err(KERIError::MgpkError(
                    "CESR deserialization not implemented".to_string(),
                ))
            }
        }
    }

    ///
    /// # Parameters:
    /// * `sad`: Optional data to serialize. If None, uses default empty data
    /// * `kind`: Serialization format (Json, Cbor, MsgPack)
    /// * `proto`: Optional protocol type
    /// * `vrsn`: Optional protocol version
    ///
    /// # Returns:
    /// Serialized bytes of the data
    ///
    /// # Errors:
    /// Returns a KERIError if serialization fails
    pub fn dumps(sad: &Sadder, kind: &Kinds) -> Result<Vec<u8>, KERIError> {
        match kind {
            Kinds::Json => match serde_json::to_string(sad) {
                Ok(json_str) => Ok(json_str.into_bytes()),
                Err(e) => Err(KERIError::DeserializeError(e.to_string())),
            },
            Kinds::Mgpk => {
                Err(KERIError::DeserializeError(
                    "MsgPack serialization not enabled".to_string(),
                ))
            }
            Kinds::Cbor => {
                Err(KERIError::DeserializeError(
                    "CBOR serialization not enabled".to_string(),
                ))
            }
            Kinds::Cesr => {
                Err(KERIError::DeserializeError(
                    "CESR serialization not enabled".to_string(),
                ))
            }
        }
    }

    pub fn verify(&self) -> Result<(), KERIError> {
        // Call the potentially overridden _verify method
        self._verify()
    }

    /// Makify given sad dict makes the versions string and computes the said
    /// field values and sets associated properties:
    /// raw, sad, proto, version, kind, size
    ///
    /// Override for protocol and ilk specific saidification behavior. Especially
    /// for inceptive ilks that have more than one said field like a said derived
    /// identifier prefix.
    ///
    /// Default prioritization:
    ///    Use method parameter if not None
    ///    Else use provided version string if valid
    ///    Otherwise use class attribute
    ///
    /// # Parameters
    /// * `sad` - Serializable saidified field map of message
    /// * `proto` - Optional desired protocol type str value of Protocols.
    ///             If None then its extracted from sad or uses default .Proto
    /// * `vrsn` - Optional instance desired protocol version.
    ///            If None then its extracted from sad or uses default .Vrsn
    /// * `kind` - Optional serialization kind string value of Serials.
    ///            supported kinds are 'json', 'cbor', 'msgpack', 'binary'.
    ///            If None then its extracted from sad or uses default .Kind
    /// * `ilk` - Optional desired ilk packet type str value of Ilks.
    ///           If None then its extracted from sad or uses default .Ilk
    /// * `saids` - Optional dict keyed by label of codes for saidive fields to
    ///             override defaults given in .Fields for a given ilk.
    ///             If None then use defaults
    pub fn makify(
        &mut self,
        sad: &Sadder,
        proto: Option<String>,
        vrsn: Option<Versionage>,
        kind: Option<Kinds>,
        ilk: Option<Ilk>,
        saids: Option<HashMap<&str, String>>) -> Result<(), KERIError> {

        // Determine protocol to use
        let proto = proto.or_else(|| {
            // Extract from sad (this would need implementation details)
            Some("KERI".to_string())
        }).unwrap_or_else(|| self.proto.clone());

        // Determine version to use
        let vrsn = vrsn.or_else(|| {
            // Extract from sad (this would need implementation details)
            Some(VRSN_1_0)
        }).unwrap_or_else(|| self.vrsn.clone());

        // Determine kind to use
        let kind = kind.or_else(|| {
            // Extract from sad (this would need implementation details)
            Some(Kinds::Json)
        }).unwrap_or_else(|| self.kind.clone());

        let ilk = ilk.unwrap_or_else(|| {Ilk::Icp});

        // Update sad with the determined values
        let sad = &mut Sadder::default_with_type(ilk, sad);

        // Create a map of SAID fields that need to be computed
        let mut said_fields: HashMap<&str, String> = HashMap::new();
        match sad.t.as_str() {
            "icp" | "dip" => {
                said_fields.insert("d", mtr_dex::BLAKE3_256.to_string()); // Blake3_256
                if !sad.i.clone().unwrap().is_empty() {
                    match BaseMatter::from_qb64(&sad.i.clone().unwrap()) {
                        Ok(mtr) => {
                            let code = String::from(mtr.code().clone());
                            if dig_dex::TUPLE.contains(&code.as_str()) {
                                said_fields.insert("i", code);
                            }
                        }
                        Err(_) => {
                            said_fields.insert("i", mtr_dex::BLAKE3_256.to_string()); // Blake3_256
                        }
                    }
                } else {
                    said_fields.insert("i", mtr_dex::BLAKE3_256.to_string()); // Blake3_256
                }
            },
            "rot" | "drt" | "vrt" | "rev" | "brv" => {
                said_fields.insert("d", mtr_dex::BLAKE3_256.to_string()); // Blake3_256
            },
            "ixn" | "rct" => {
                said_fields.insert("d", mtr_dex::BLAKE3_256.to_string()); // Blake3_256
            },
            "qry" | "rpy" | "pro" | "bar" | "exn" => {
                said_fields.insert("d", mtr_dex::BLAKE3_256.to_string()); // Blake3_256
            },
            "vcp" => {
                said_fields.insert("d", mtr_dex::BLAKE3_256.to_string()); // Blake3_256
                said_fields.insert("i", mtr_dex::BLAKE3_256.to_string()); // Blake3_256
            },
            "iss" => {
                said_fields.insert("d", mtr_dex::BLAKE3_256.to_string()); // Blake3_256
            },
            "bis" => {
                said_fields.insert("d", mtr_dex::BLAKE3_256.to_string()); // Blake3_256
            },
            _ => {} // No digestive fields for other types
        }

        // Override with provided SAIDs if any
        if let Some(saids) = saids.clone() {
            for (label, code) in saids {
                said_fields.insert(label, code.to_string());
            }
        }

        // Handle saidive fields
        sad.set_said_placeholders(saids);
        self.prepare_version(sad, kind.clone(), proto.clone(), vrsn.clone())?;
        // Serialize sad to raw based on kind
        let raw = Self::dumps(&sad, &kind)?;

        println!("Raw: {:}", String::from_utf8(raw.clone()).unwrap());

        // Compute the digest for each SAID field
        for (label, code) in said_fields {
            // Check if the code is digestive (in DigDex)
            if dig_dex::TUPLE.contains(&code.as_str()) {
                let diger = Diger::from_ser_and_code(&raw, code.as_str()).map_err(|e| KERIError::from(e))?;
                let qb64 = diger.qb64();

                // Update the field based on the label
                match label {
                    "d" => sad.d = qb64,
                    "i" => if let Some(i) = &mut sad.i {
                        *i = qb64;
                    } else {
                        sad.i = Some(qb64);
                    },
                    // Add other fields as needed
                    _ => {} // Ignore unknown fields
                }
            }
        }

        // Serialize the final data with updated SAIDs
        let raw = Self::dumps(&sad, &kind)?;

        // Compute SAID (Self-Addressing IDentifier) for the sad
        let said = if sad.d.is_empty() { sad.i.clone() } else {Some(sad.d.clone())};

        // Update object properties
        self.raw = raw;
        self.sad = sad.clone();
        self.proto = proto;
        self.vrsn = vrsn;
        self.kind = kind;
        self.said = said;
        // For CESR kind, just compute the size of the whole message, not sure why this matters?
        let size = if kind == Kinds::Cesr {
            self.raw.len()
        } else {
            self.raw.len()
        };

        self.size = size;

        Ok(())
    }

}

/// Trait representing a serializable/deserializable entity with SAID (Self-Addressing IDentifier)
pub trait Serder: Any + Send + Sync {
    /// Returns a pretty-printed JSON representation of the serialized data
    ///
    /// # Parameters
    /// * `size` - Optional size limit for the output. None means no limit.
    ///   This protects against syslog errors when exceeding UDP MTU.
    ///   IPv4 MTU is 576, IPv6 MTU is 1280, and most broadband routers have 1454 MTU.
    fn pretty(&self, size: Option<usize>) -> String;

    /// Returns the raw bytes representation
    fn raw(&self) -> &[u8];

    /// Returns a copy of the serializable attribute dictionary (saidified data)
    fn sad(&self) -> Sadder;

    /// Returns the CESR genus code for this Serder
    fn genus(&self) -> &str;

    /// Returns the CESR genus code table version for this Serder
    fn gvrsn(&self) -> &Versionage;

    /// Returns the serialization kind (value of Serials/Serialage)
    fn kind(&self) -> &Kinds;

    /// Returns the protocol identifier type (e.g., 'KERI' or 'ACDC')
    fn proto(&self) -> &str;

    /// Alias for proto() - returns the protocol identifier type
    fn protocol(&self) -> &str {
        self.proto()
    }

    /// Returns the protocol version for this Serder
    fn vrsn(&self) -> &Versionage;

    /// Alias for vrsn() - returns the protocol version
    fn version(&self) -> &Versionage {
        self.vrsn()
    }

    /// Returns the number of bytes in the raw representation
    fn size(&self) -> usize;

    /// Returns the qb64 SAID (Self-Addressing IDentifier)
    fn said(&self) -> Option<&str>;

    /// Returns the qb64b (bytes) representation of the SAID
    fn saidb(&self) -> Option<Vec<u8>> {
        self.said().map(|s| s.as_bytes().to_vec())
    }

    /// Returns the packet type given by sad['t'] if any
    fn ilk(&self) -> Option<&str>;

    fn as_any(&self) -> &dyn Any;

}

impl Serder for BaseSerder {
    fn pretty(&self, size: Option<usize>) -> String {
        let json_str = serde_json::to_string_pretty(&self.sad)
            .unwrap_or_else(|_| "Error serializing to JSON".to_string());

        if let Some(limit) = size {
            if json_str.len() > limit {
                return json_str[..limit].to_string();
            }
        }

        json_str
    }

    fn raw(&self) -> &[u8] {
        &self.raw
    }

    fn sad(&self) -> Sadder {
        self.sad.clone() // Return a copy
    }

    fn genus(&self) -> &str {
        &self.genus
    }

    fn gvrsn(&self) -> &Versionage {
        &self.gvrsn
    }

    fn kind(&self) -> &Kinds {
        &self.kind
    }

    fn proto(&self) -> &str {
        &self.proto
    }

    fn vrsn(&self) -> &Versionage {
        &self.vrsn
    }

    fn size(&self) -> usize {
        self.size
    }

    fn said(&self) -> Option<&str> {
        self.said.as_deref()
    }

    fn ilk(&self) -> Option<&str> {
        Some(self.sad.t.as_str())
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

// Define a trait for verification behavior
pub trait Verifiable {
    // Default implementation that can be overridden
    fn _verify(&self) -> Result<(), KERIError> {
        // Default behavior
        Ok(())
    }
}

// Implement the trait for BaseSerder
impl Verifiable for BaseSerder {
    // You can override the default implementation if needed
    fn _verify(&self) -> Result<(), KERIError> {
        // Verify that the required SAID field is present. This is a critical field for integrity checks.
        if let Some(said) = &self.said {
            // Compute the expected SAID based on the self-addressing hash of the serialized message.
            // Create a map of SAID fields that need to be computed
            let mut sad = self.sad.clone();
            sad.set_said_placeholders(None);
            let raw = Self::dumps(&sad, &self.kind)?;

            let dcoder = Diger::from_qb64(said);
            let diger = Diger::from_ser_and_code(&raw, dcoder.unwrap().code()).map_err(|e| KERIError::from(e))?;
            let qb64 = diger.qb64();
            if said != &qb64 {
                return Err(KERIError::ValidationError(format!(
                    "SAID mismatch: expected {}, found {}",
                    qb64, said
                )));
            }
        } else {
            // If the SAID is None, verification fails since it's a required field.
            return Err(KERIError::FieldError("Missing SAID field.".to_string()));
        }

        // Additional checks can be added here for other required fields or properties.

        Ok(())
    }
}


/// KERI-specific implementation of the Serder
#[derive(Debug, Clone)]
pub struct SerderKERI {
    base: BaseSerder,
}

/// Implement the Serder trait for SerderKERI
impl Serder for SerderKERI {
    fn pretty(&self, size: Option<usize>) -> String { self.base.pretty(size) }
    fn raw(&self) -> &[u8] { self.base.raw() }
    fn sad(&self) -> Sadder { self.base.sad() }
    fn genus(&self) -> &str { self.base.genus() }
    fn gvrsn(&self) -> &Versionage { self.base.gvrsn() }
    fn kind(&self) -> &Kinds { self.base.kind() }
    fn proto(&self) -> &str { self.base.proto() }
    fn vrsn(&self) -> &Versionage { self.base.vrsn() }
    fn size(&self) -> usize { self.base.size() }
    fn said(&self) -> Option<&str> { self.base.said() }
    fn ilk(&self) -> Option<&str> { self.base.ilk() }
    fn as_any(&self) -> &dyn Any { self }
}

impl SerderKERI {
    /// Creates a new `SerderKERI` by constructing its `BaseSerder` from raw bytes.
    pub fn from_raw(raw: &[u8], smell: Option<Smellage>) -> Result<Self, KERIError> {
        let base = BaseSerder::from_raw(raw, smell)?;
        Ok(Self { base })
    }

    /// Creates a new `SerderKERI` by constructing its `BaseSerder` from a sad.
    pub fn from_sad(sad: &Sadder) -> Result<Self, KERIError> {
        let base = BaseSerder::from_sad(sad)?;
        Ok(Self { base })
    }

    /// Returns true if Serder represents an establishment event
    pub fn estive(&self) -> bool {
        let t = self.base.sad.t.as_str();
        matches!(t, "icp" | "rot" | "dip" | "drt")
    }

    /// Returns key event dict property getter. Alias for .sad
    pub fn ked(&self) -> Sadder {
        self.base.sad.clone()
    }

    /// Returns qb64 of .sad["i"] identifier prefix
    pub fn pre(&self) -> Option<String> {
        self.base.sad.i.clone()
    }

    /// Returns qb64b of .pre identifier prefix as bytes
    pub fn preb(&self) -> Option<Vec<u8>> {
        self.pre().map(|pre| pre.into_bytes())
    }

    /// Number instance of sequence number
    pub fn sner(&self) -> Option<Number> {
        let num = Number::from_numh(self.base.sad.s.as_ref().unwrap_or(&"0".to_string()));
        match num {
            Ok(num) => Some(num),
            Err(e) => {
                error!("Error parsing sequence number: {}", e);
                None
            }
        }
    }

    /// Sequence number as integer
    pub fn sn(&self) -> Option<u64> {
        match self.sner() {
            Some(num) => Some(num.num() as u64),
            None => None,
        }
    }

    /// Sequence number as hex string
    pub fn snh(&self) -> Option<String> {
        self.sner().map(|sner| sner.numh())
    }

    /// Seals from .sad["a"]
    pub fn seals(&self) -> Option<Vec<String>> {
        match &self.base.sad.a {
            Some(AttribField::StringList(list)) => {
                Some(list.clone())
            }
            Some(AttribField::StringMap(_)) => {
                None
            }
            None => None,
        }
    }

    /// Traits list (config traits) from .sad["c"]
    pub fn traits(&self) -> Option<Vec<String>> {
        self.base.sad.c.clone()
    }

    /// Tholder instance as converted from .sad['kt']
    pub fn tholder(&self) -> Option<Tholder> {
        let kt = self.base.sad.kt.clone().unwrap();
        let thold = Tholder::new(None, Some(kt.as_bytes().to_vec()), None);
        match thold {
            Ok(thold) => Some(thold),
            Err(e) => {
                error!("Error parsing threshold: {}", e);
                None
            }
        }
    }

    /// List of qb64 keys from .sad['k']
    pub fn keys(&self) -> Option<Vec<String>> {
        self.base.sad.k.clone()
    }

    /// List of Verfer instances as converted from .sad['k']
    pub fn verfers(&self) -> Option<Vec<Verfer>> {
        self.keys().and_then(|keys| {
            let mut verfers = Vec::new();
            for key in keys.iter() {
                match Verfer::from_qb64(key) {
                    Ok(verfer) => verfers.push(verfer),
                    Err(_) => return None,
                }
            }
            Some(verfers)
        })
    }

    /// Tholder instance as converted from .sad['nt']
    pub fn ntholder(&self) -> Option<Tholder> {
        let nt = self.base.sad.nt.clone().unwrap();
        let thold = Tholder::new(None, Some(nt.as_bytes().to_vec()), None);
        match thold {
            Ok(thold) => Some(thold),
            Err(e) => {
                error!("Error parsing next threshold: {}", e);
                None
            }
        }
    }

    /// Next key digests from .sad['n']
    pub fn ndigs(&self) -> Option<Vec<String>> {
        // Check version condition like in Python
        if self.base.vrsn.major < 2 && self.base.vrsn.minor < 1 && self.base.sad.t == "vcp" {
            return None;
        }

        self.base.sad.n.clone()
    }

    /// List of Diger instances as converted from .sad['n']
    pub fn ndigers(&self) -> Option<Vec<Diger>> {
        self.ndigs().and_then(|digs| {
            let mut digers = Vec::new();
            for dig in digs.iter() {
                match Diger::from_qb64(dig) {
                    Ok(diger) => digers.push(diger),
                    Err(_) => return None,
                }
            }
            Some(digers)
        })
    }

    /// Number of backer TOAD threshold
    pub fn bner(&self) -> Option<Number> {
        let num = Number::from_numh(self.base.sad.bt.as_ref().unwrap_or(&"0".to_string()));
        match num {
            Ok(num) => Some(num),
            Err(e) => {
                error!("Error parsing sequence number: {}", e);
                None
            }
        }
    }

    /// Backer TOAD number as integer
    pub fn bn(&self) -> Option<u64> {
        match self.sner() {
            Some(num) => Some(num.num() as u64),
            None => None,
        }
    }

    /// Backers list from .sad['b']
    pub fn backs(&self) -> Option<Vec<String>> {
        self.base.sad.b.clone()
    }

    /// List of Verfer instances as converted from .sad['b']
    pub fn berfers(&self) -> Option<Vec<Verfer>> {
        self.backs().and_then(|keys| {
            let mut verfers = Vec::new();
            for key in keys.iter() {
                match Verfer::from_qb64(key) {
                    Ok(verfer) => verfers.push(verfer),
                    Err(_) => return None,
                }
            }
            Some(verfers)
        })
    }

    /// Prior event SAID from .sad['p']
    pub fn prior(&self) -> Option<String> {
        self.base.sad.p.clone()
    }

    /// Prior event SAID as bytes
    pub fn priorb(&self) -> Option<Vec<u8>> {
        self.prior().map(|prior| prior.into_bytes())
    }

    /// List of backers to be cut (removed) from .sad['br']
    pub fn cuts(&self) -> Option<Vec<String>> {
        self.base.sad.br.clone()
    }

    /// List of backers to be added from .sad['ba']
    pub fn adds(&self) -> Option<Value> {
        self.base.sad.ba.clone()
    }

    /// Delegator ID prefix from .sad["di"]
    pub fn delpre(&self) -> Option<String> {
        self.base.sad.di.clone()
    }

    /// Delegator ID prefix as bytes
    pub fn delpreb(&self) -> Option<Vec<u8>> {
        self.delpre().map(|delpre| delpre.into_bytes())
    }

    /// Date-time-stamp from .sad["dt"]
    pub fn stamp(&self) -> Option<String> {
        self.base.sad.dt.clone()
    }

    /// UUID (salty nonce) from .sad["u"]
    pub fn uuid(&self) -> Option<String> {
        self.base.sad.u.clone()
    }

    /// Alias for .uuid property with version check
    pub fn nonce(&self) -> Option<String> {
        if self.base.vrsn.major < 2 && self.base.vrsn.minor < 1 && self.base.sad.t == "vcp" {
            // In earlier versions, nonce was stored in 'n' field
            self.base.sad.n.as_ref().map(|n| n[0].clone())
        } else {
            self.uuid()
        }
    }

    /// Get the ilk of the event
    pub fn ilk(&self) -> Option<Ilk> {
        Ilk::from_str(&self.base.sad.t)
    }
}

// Override the verification for the derived struct
impl Verifiable for SerderKERI {
    fn _verify(&self) -> Result<(), KERIError> {
        // First call the base implementation
        self.base._verify()?;

        // Then add SerderKERI-specific verification
        // Additional verification logic here

        Ok(())
    }
}

/// Helper function to parse version string into Versionage
fn parse_version(version_str: &str) -> Result<Versionage, String> {
    let parts: Vec<&str> = version_str.split('.').collect();

    if parts.len() != 2 {
        return Err(format!("Invalid version format: {}", version_str));
    }

    let major = match parts[0].parse::<u32>() {
        Ok(num) => num,
        Err(_) => return Err(format!("Invalid major version: {}", parts[0])),
    };

    let minor = match parts[1].parse::<u32>() {
        Ok(num) => num,
        Err(_) => return Err(format!("Invalid minor version: {}", parts[1])),
    };

    Ok(Versionage { major, minor })
}

/// SerderACDC struct that extends BaseSerder
#[derive(Debug, Clone)]
pub struct SerderACDC {
    /// Base Serder fields and behavior
    pub base: BaseSerder,
}

/// Implement the Serder trait for SerderKERI
impl Serder for SerderACDC {
    fn pretty(&self, size: Option<usize>) -> String { self.base.pretty(size) }
    fn raw(&self) -> &[u8] { self.base.raw() }
    fn sad(&self) -> Sadder { self.base.sad() }
    fn genus(&self) -> &str { self.base.genus() }
    fn gvrsn(&self) -> &Versionage { self.base.gvrsn() }
    fn kind(&self) -> &Kinds { self.base.kind() }
    fn proto(&self) -> &str { self.base.proto() }
    fn vrsn(&self) -> &Versionage { self.base.vrsn() }
    fn size(&self) -> usize { self.base.size() }
    fn said(&self) -> Option<&str> { self.base.said() }
    fn ilk(&self) -> Option<&str> { self.base.ilk() }
    fn as_any(&self) -> &dyn Any { self }
}



impl SerderACDC {
    /// Creates a new `SerderACDC` by constructing its `BaseSerder` from raw bytes.
    pub fn from_raw(raw: &[u8], smell: Option<Smellage>) -> Result<Self, KERIError> {
        let base = BaseSerder::from_raw(raw, smell)?;
        Ok(Self { base })
    }

    /// Creates a new `SerderACDC` by constructing its `BaseSerder` from a sad.
    pub fn from_sad(sad: &Sadder) -> Result<Self, KERIError> {
        let base = BaseSerder::from_sad(sad)?;
        Ok(Self { base })
    }


    /// uuid property getter
    /// Optional fields return None when not present
    ///
    /// Returns:
    ///    Option<String>: qb64 of .sad["u"] salty nonce
    pub fn uuid(&self) -> Option<&str> {
        if let Some(value) = self.base.sad.u.as_ref() {
            return Some(value);
        }
        None
    }

    /// uuidb property getter (uuid bytes)
    /// Optional fields return None when not present
    ///
    /// Returns:
    ///    Option<Vec<u8>>: qb64b of .sad["u"] salty nonce as bytes
    pub fn uuidb(&self) -> Option<Vec<u8>> {
        self.uuid().map(|s| s.as_bytes().to_vec())
    }

    /// issuer property getter (issuer AID)
    /// Optional fields return None when not present
    ///
    /// Returns:
    ///    Option<String>: qb64 of .sad["i"] issuer AID
    pub fn issuer(&self) -> Option<&str> {
        if let Some(value) = self.base.sad.i.as_ref() {
            return Some(value.as_str())
        }
        None
    }

    /// issuerb property getter (issuer AID bytes)
    /// Optional fields return None when not present
    ///
    /// Returns:
    ///    Option<Vec<u8>>: qb64b of .issuer AID as bytes
    pub fn issuerb(&self) -> Option<Vec<u8>> {
        self.issuer().map(|s| s.as_bytes().to_vec())
    }

    /// regi property getter (registry identifier SAID)
    /// Optional fields return None when not present
    ///
    /// Returns:
    ///    Option<String>: qb64 of .sad["ri"] registry SAID
    pub fn regi(&self) -> Option<&str> {
        if let Some(value) = self.base.sad.ri.as_ref() {
            return Some(value.as_str())
        }
        None
    }

    /// regib property getter (registry identifier SAID bytes)
    /// Optional fields return None when not present
    ///
    /// Returns:
    ///    Option<Vec<u8>>: qb64b of .issuer AID as bytes
    pub fn regib(&self) -> Option<Vec<u8>> {
        // Note: There's a bug in the Python implementation that uses self.issuer here
        // Fixing it to use self.regi instead
        self.regi().map(|s| s.as_bytes().to_vec())
    }

    /// schema block or SAID property getter
    /// Optional fields return None when not present
    ///
    /// Returns:
    ///    Option<&Value>: from ._sad["s"]
    pub fn schema(&self) -> Option<&String> {
        self.base.sad.s.as_ref()
    }

    /// attrib block or SAID property getter (attribute)
    /// Optional fields return None when not present
    ///
    /// Returns:
    ///    Option<&String>: from ._sad["a"]
    pub fn attrib(&self) -> Option<HashMap<String, String>> {
        match &self.base.sad.a {
            Some(AttribField::StringMap(map)) => Some(map.clone()),
            Some(AttribField::StringList(_)) => None,
            None => None,
        }
    }

    /// issuee property getter (issuee AID)
    /// Optional fields return None when not present
    ///
    /// Returns:
    ///    Option<String>: qb64 of .sad["a"]["i"] issuee AID
    pub fn issuee(&self) -> Option<&str> {
        match &self.base.sad.a {
            Some(AttribField::StringMap(map)) => {
                map.get("i").map(|s| s.as_str())
            }
            Some(AttribField::StringList(_)) => None,
            None => None,
        }
    }

    /// issueeb property getter (issuee AID bytes)
    /// Optional fields return None when not present
    ///
    /// Returns:
    ///    Option<Vec<u8>>: qb64b of .issuee AID as bytes
    pub fn issueeb(&self) -> Option<Vec<u8>> {
        self.issuee().map(|s| s.as_bytes().to_vec())
    }

    /// attagg block property getter (attribute aggregate)
    /// Optional fields return None when not present
    ///
    /// Returns:
    ///    Option<&Value>: from ._sad["A"]
    pub fn attagg(&self) -> Option<&Vec<String>> {
        self.base.sad.cap_a.as_ref()
    }

    /// edge block property getter
    /// Optional fields return None when not present
    ///
    /// Returns:
    ///    Option<&Value>: from ._sad["e"]
    pub fn edge(&self) -> Option<&Value> {
        self.base.sad.e.as_ref()
    }

    /// rule block property getter
    /// Optional fields return None when not present
    ///
    /// Returns:
    ///    Option<&Value>: from ._sad["r"]
    pub fn rule(&self) -> Option<&String> {
        self.base.sad.r.as_ref()
    }
}

// Implement the Serder trait for SerderACDC (assuming we have a trait as discussed)
impl Verifiable for SerderACDC {
    fn _verify(&self) -> Result<(), KERIError> {
        // First verify base fields
        self.base._verify()?;

        // Add ACDC-specific verification
        // This could include validating the schema, issuer, etc.

        Ok(())
    }
}

impl SerderACDC {
    /// Public verification method that delegates to the trait method
    pub fn verify(&self) -> Result<(), KERIError> {
        self._verify()
    }
}

/// Serder factory for generating serder instances by protocol type
pub struct Serdery;

impl Serdery {
    /// Create a new Serdery instance
    pub fn new() -> Self {
        Serdery
    }

    /// Extract and return Serder implementation based on protocol type detected in message
    ///
    /// # Arguments
    /// * `ims` - Serialized incoming message stream. Assumes start of stream is raw Serder.
    /// * `genus` - CESR genus code from stream parser.
    /// * `gvrsn` - Instance CESR genus code table version (Major, Minor)
    /// * `native` - True means may be CESR native message so snuff instead of smell.
    ///             False means not CESR native i.e JSON, CBOR, MGPK field map, so use smell.
    /// * `skip` - Bytes to skip at front of ims. Useful for CESR native serialization.
    ///
    /// # Returns
    /// Box<dyn Serder> - Instance of appropriate Serder implementation
    pub fn reap(
        &self,
        ims: &[u8],
        _genus: &str,
        _gvrsn: &Versionage,
        native: Option<bool>,
        skip: Option<usize>
    ) -> Result<Box<dyn Serder>, KERIError> {
        let native = native.unwrap_or(false);
        let skip = skip.unwrap_or(0);

        let smellage = if native {
            // Handle CESR native case, skipping bytes if necessary
            if skip > 0 && skip < ims.len() {
                smell(&ims[skip..])
            } else {
                smell(ims)
            }
        } else {
            smell(ims)
        }?;

        let protos = Protocolage::default();
        if smellage.proto == protos.keri {
            // Create SerderKERI instance
            let serder = SerderKERI::from_raw(ims, Some(smellage))?;
            Ok(Box::new(serder))
        } else if smellage.proto == protos.acdc {
            // Create SerderACDC instance
            let serder = SerderACDC::from_raw(ims, Some(smellage))?;
            Ok(Box::new(serder))
        } else {
            Err(KERIError::ProtocolError(format!("Unsupported protocol type = {}", smellage.proto)))
        }
    }
}


#[cfg(test)]
mod tests {
    use crate::cesr::VRSN_1_0;
    use crate::keri::{Ilk, Kinds};
    use crate::keri::core::serdering::{AttribField, BaseSerder, Sadder, Serder, SerderKERI};

    #[test]
    fn test_valid_icp_event() {
        let icp_event = Sadder {
            v: "KERI10JSON00011c_".to_string(),
            t: "icp".to_string(),
            d: "EL1L56LyoKrIofnn0q7_eKmLBELDT-8rS-7wjTuELmzQ".to_string(),
            i: Some("EL1L56LyoKrIofnn0q7_eKmLBELDT-8rS-7wjTuELmzQ".to_string()),
            s: Some("0".to_string()),
            kt: Some("1".to_string()),
            k: Some(vec!["DQbYDpQRN5cmkQ94mR69N_c98C0-SIVYEj2LM2VAGUhZ".to_string()]),
            nt: Some("1".to_string()),
            n: Some(vec!["EsgNZjFXMI8szR6N5eG8OsHqXxyKWrYCkP9mGkYAjS3Y".to_string()]),
            bt: Some("0".to_string()),
            b: Some(vec![]),
            c: Some(vec![]),
            ..Default::default()
        };

        assert!(icp_event.validate().is_ok());
    }

    #[test]
    fn test_invalid_icp_event() {
        // Missing k field which is required for icp events
        let invalid_icp = Sadder {
            v: "KERI10JSON00011c_".to_string(),
            t: "icp".to_string(),
            d: "EL1L56LyoKrIofnn0q7_eKmLBELDT-8rS-7wjTuELmzQ".to_string(),
            i: Some("EL1L56LyoKrIofnn0q7_eKmLBELDT-8rS-7wjTuELmzQ".to_string()),
            s: Some("0".to_string()),
            kt: Some("1".to_string()),
            // k field is missing
            nt: Some("1".to_string()),
            n: Some(vec!["EsgNZjFXMI8szR6N5eG8OsHqXxyKWrYCkP9mGkYAjS3Y".to_string()]),
            bt: Some("0".to_string()),
            b: Some(vec![]),
            c: Some(vec![]),
            ..Default::default()
        };

        assert!(invalid_icp.validate().is_err());
    }

    #[test]
    fn test_serder_initialization_and_verification() {
        // Test creating a Serder with makify=true and icp ilk
        let serder = BaseSerder::from_init(None, None, Some(true), None, None, None, None, None, None).unwrap();

        // Check the generated SAD structure
        let sad = serder.sad();
        assert_eq!(sad.t, "icp");
        assert_eq!(sad.s.as_ref().unwrap(), "0");
        assert_eq!(sad.kt.as_ref().unwrap(), "0");
        assert_eq!(sad.nt.as_ref().unwrap(), "0");
        assert_eq!(sad.bt.as_ref().unwrap(), "0");
        assert!(sad.k.as_ref().unwrap().is_empty());
        assert!(sad.n.as_ref().unwrap().is_empty());
        assert!(sad.b.as_ref().unwrap().is_empty());
        assert!(sad.c.as_ref().unwrap().is_empty());

        // In Python there's an assert for 'a' field, assuming it exists in Rust as well
        match &sad.a {
            Some(AttribField::StringList(list)) => assert!(list.is_empty()),
            Some(AttribField::StringMap(map)) => assert!(map.is_empty()),
            None => panic!("Expected 'a' field to exist but be empty"),
        }

        // Verify the SAID is consistent
        assert_eq!(sad.d, sad.i.clone().unwrap());

        // Get raw bytes and verify they match the expected pattern
        let raw = serder.raw();
        assert!(raw.starts_with(b"{\"v\":\"KERI10JSON"));
        // assert!(raw.contains(b"\"t\":\"icp\""));

        // Verify other properties
        // assert!(serder.verify().is_ok());
        assert_eq!(serder.ilk().unwrap(), "icp");

        // Store values for reconstruction tests
        let sad_clone = serder.sad().clone();
        let raw_clone = serder.raw().clone();
        let said = serder.said().clone();
        let size = serder.size();

        // Test reconstruction from SAD
        let serder_from_sad = SerderKERI::from_sad(&sad_clone).unwrap();
        assert_eq!(serder_from_sad.raw(), raw_clone);
        assert_eq!(serder_from_sad.sad().d, sad.d);
        assert_eq!(serder_from_sad.proto(), "KERI");
        assert_eq!(serder_from_sad.vrsn(), &VRSN_1_0);
        assert_eq!(serder_from_sad.size(), size);
        assert_eq!(serder_from_sad.kind(), &Kinds::Json);
        assert_eq!(serder_from_sad.said(), said);
        assert_eq!(serder_from_sad.ilk().unwrap(), Ilk::Icp);

        // Test reconstruction from raw bytes
        let serder_from_raw = SerderKERI::from_raw(&raw_clone, None).unwrap();
        assert_eq!(serder_from_raw.raw(), raw_clone);

        // Check that SAD matches between original and reconstructed from raw
        let regenerated_sad = serder_from_raw.sad();
        assert_eq!(regenerated_sad.v, sad.v);
        assert_eq!(regenerated_sad.t, sad.t);
        assert_eq!(regenerated_sad.d, sad.d);
        assert_eq!(regenerated_sad.i, sad.i);

        // Additional verification
        assert_eq!(serder_from_raw.proto(), "KERI");
        assert_eq!(serder_from_raw.vrsn(), &VRSN_1_0);
        assert_eq!(serder_from_raw.size(), size);
        assert_eq!(serder_from_raw.kind(), &Kinds::Json);
        assert_eq!(serder_from_raw.said(), said);
        assert_eq!(serder_from_raw.ilk().unwrap(), Ilk::Icp);

        // Test creating a Serder with makify=true and icp ilk
        let mut sad = Sadder::default();
        sad.i = Some("DKxy2sgzfplyr-tgwIxS19f2OchFHtLwPWD3v4oYimBx".to_string());
        let serder = BaseSerder::from_init(None, Some(&sad), Some(true), None, None, None, None, None, None).unwrap();
        assert_eq!(serder.sad().i, sad.i);
        assert_eq!(serder.sad().d, "EIXK39EgyxshefoCdSpKCkG5FR9s405YI4FAHDvAqO_R");
    }

}
