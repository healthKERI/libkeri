mod sad;

pub use sad::SadValue;
pub use sad::Sadder;

use crate::cesr::counting::gen_dex;
use crate::cesr::diger::Diger;
use crate::cesr::number::Number;
use crate::cesr::tholder::Tholder;
use crate::cesr::verfer::Verfer;
use crate::cesr::{dig_dex, mtr_dex, BaseMatter, Versionage, VRSN_1_0};
use crate::keri::core::serdering::sad::{
    default_with_type, get_primary_said_label, set_said_placeholders,
};
use crate::keri::{deversify, smell, versify, Ilk, KERIError, Kinds, Protocolage, Said, Smellage};
use crate::Matter;
use base64::prelude::BASE64_STANDARD;
use base64::Engine;
use indexmap::IndexMap;
use serde_json::{self};
use std::any::Any;
use std::collections::HashMap;
use tracing::error;

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
        _ => Err(KERIError::VersionError(
            "Unsupported version and kind combination".to_string(),
        )),
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
    pub fn from_init(
        raw: Option<&[u8]>,
        sad: Option<&Sadder>,
        makify: Option<bool>,
        smellage: Option<Smellage>,
        proto: Option<String>,
        vrsn: Option<Versionage>,
        kind: Option<Kinds>,
        ilk: Option<Ilk>,
        saids: Option<HashMap<&str, String>>,
    ) -> Result<Self, KERIError> {
        let mfy = makify.unwrap_or(true);

        match raw {
            Some(raw) => Self::from_raw(raw, smellage),
            None => {
                if mfy {
                    let mut serder = Self::default();
                    serder.makify(
                        sad.unwrap_or(&Sadder::default()),
                        proto,
                        vrsn,
                        kind,
                        ilk,
                        saids,
                    )?;
                    Ok(serder)
                } else {
                    match sad {
                        Some(sad) => Self::from_sad(sad),
                        None => Err(KERIError::MissingRequiredField(
                            "raw".to_string(),
                            "Raw or Sad required".to_string(),
                        ))?,
                    }
                }
            }
        }
    }

    pub fn from_sad(sad: &Sadder) -> Result<Self, KERIError> {
        let genus = String::from(gen_dex::KERI);
        let ver = sad.get("v").unwrap().as_str().unwrap();

        let smell = deversify(ver.as_bytes())?;
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
            gvrsn: gvrsn
                .ok_or_else(|| KERIError::FieldError("Missing required gvrsn value".to_string()))?,
        };

        // Get the primary said field label
        let label = match get_primary_said_label(sad) {
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
                serder.said = Some(sad["d"].as_str().unwrap().to_string());
            }
            _ => {
                return Err(KERIError::FieldError(format!(
                    "Missing primary said field in {:?}.",
                    sad
                )));
            }
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
    pub fn prepare_version(
        &self,
        sad: &mut Sadder,
        kind: Kinds,
        proto: String,
        vrsn: Versionage,
    ) -> Result<(), KERIError> {
        // Only process for these serialization formats
        if matches!(kind, Kinds::Json | Kinds::Cbor | Kinds::Mgpk) {
            // Dummy character for padding
            let dummy = "#";

            // Get the span length for this version
            let span = get_version_span(&vrsn, &kind)?;

            // Pad the version field with dummy characters to ensure proper span
            sad.insert("v".to_string(), SadValue::String(dummy.repeat(span)));

            // Serialize to calculate the size
            let raw = Self::dumps(&sad, &kind)?;
            let size = raw.len();

            // Generate the correct version string with the calculated size
            let vs = versify(
                proto.as_str(),
                &vrsn,
                kind.to_string().as_str(),
                size as u64,
            )?;

            // Update the version string in the Sadder
            sad.insert("v".to_string(), SadValue::String(vs));
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
        get_primary_said_label(&self.sad)
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
                let sadder =
                    rmp_serde::from_slice(data).map_err(|e| KERIError::MgpkError(e.to_string()))?;
                Ok(sadder)
            }

            Kinds::Cbor => {
                let sadder = serde_cbor::from_slice(data)
                    .map_err(|e| KERIError::CborError(e.to_string()))?;
                Ok(sadder)
            }
            Kinds::Cesr => Err(KERIError::MgpkError(
                "CESR deserialization not implemented".to_string(),
            )),
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
            Kinds::Mgpk => match rmp_serde::to_vec(sad) {
                Ok(mgpk_bytes) => Ok(mgpk_bytes),
                Err(e) => Err(KERIError::DeserializeError(e.to_string())),
            },
            Kinds::Cbor => match serde_cbor::to_vec(sad) {
                Ok(cbor_bytes) => Ok(cbor_bytes),
                Err(e) => Err(KERIError::DeserializeError(e.to_string())),
            },
            Kinds::Cesr => Err(KERIError::DeserializeError(
                "CESR serialization not enabled".to_string(),
            )),
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
        saids: Option<HashMap<&str, String>>,
    ) -> Result<(), KERIError> {
        // Determine protocol to use
        let proto = proto
            .or_else(|| {
                // Extract from sad (this would need implementation details)
                Some("KERI".to_string())
            })
            .unwrap_or_else(|| self.proto.clone());

        // Determine version to use
        let vrsn = vrsn
            .or_else(|| {
                // Extract from sad (this would need implementation details)
                Some(VRSN_1_0)
            })
            .unwrap_or_else(|| self.vrsn.clone());

        // Determine kind to use
        let kind = kind
            .or_else(|| {
                // Extract from sad (this would need implementation details)
                Some(Kinds::Json)
            })
            .unwrap_or_else(|| self.kind.clone());

        let ilk = ilk.unwrap_or_else(|| Ilk::Icp);

        // Update sad with the determined values
        let mut sad = default_with_type(ilk, sad);

        // Create a map of SAID fields that need to be computed
        let mut said_fields: HashMap<&str, String> = HashMap::new();
        match sad["t"].as_str().unwrap() {
            "icp" | "dip" => {
                said_fields.insert("d", mtr_dex::BLAKE3_256.to_string()); // Blake3_256
                match sad.get("i") {
                    Some(SadValue::String(i)) if !i.is_empty() => {
                        match BaseMatter::from_qb64(&i.clone()) {
                            Ok(mtr) => {
                                let code = String::from(mtr.code().clone());
                                if dig_dex::TUPLE.contains(&code.as_str()) {
                                    said_fields.insert("i", code);
                                }
                            }
                            Err(_) => {
                                said_fields.insert("i", mtr_dex::BLAKE3_256.to_string());
                                // Blake3_256
                            }
                        }
                    }
                    _ => {
                        said_fields.insert("i", mtr_dex::BLAKE3_256.to_string());
                        // Blake3_256
                    }
                }
            }
            "rot" | "drt" | "vrt" | "rev" | "brv" => {
                said_fields.insert("d", mtr_dex::BLAKE3_256.to_string()); // Blake3_256
            }
            "ixn" | "rct" => {
                said_fields.insert("d", mtr_dex::BLAKE3_256.to_string()); // Blake3_256
            }
            "qry" | "rpy" | "pro" | "bar" | "exn" => {
                said_fields.insert("d", mtr_dex::BLAKE3_256.to_string()); // Blake3_256
            }
            "vcp" => {
                said_fields.insert("d", mtr_dex::BLAKE3_256.to_string()); // Blake3_256
                said_fields.insert("i", mtr_dex::BLAKE3_256.to_string()); // Blake3_256
            }
            "iss" => {
                said_fields.insert("d", mtr_dex::BLAKE3_256.to_string()); // Blake3_256
            }
            "bis" => {
                said_fields.insert("d", mtr_dex::BLAKE3_256.to_string()); // Blake3_256
            }
            _ => {} // No digestive fields for other types
        }

        // Override with provided SAIDs if any
        if let Some(saids) = saids.clone() {
            for (label, code) in saids {
                said_fields.insert(label, code.to_string());
            }
        }

        // Handle saidive fields
        set_said_placeholders(&mut sad, saids);
        self.prepare_version(&mut sad, kind.clone(), proto.clone(), vrsn.clone())?;
        // Serialize sad to raw based on kind
        let raw = Self::dumps(&sad, &kind)?;

        println!("Raw: {:}", String::from_utf8(raw.clone()).unwrap());

        // Compute the digest for each SAID field
        for (label, code) in said_fields {
            // Check if the code is digestive (in DigDex)
            if dig_dex::TUPLE.contains(&code.as_str()) {
                let diger = Diger::from_ser_and_code(&raw, code.as_str())
                    .map_err(|e| KERIError::from(e))?;
                let qb64 = diger.qb64();

                // Update the field based on the label
                sad.insert(label.to_string(), SadValue::String(qb64));
            }
        }

        // Serialize the final data with updated SAIDs
        let raw = Self::dumps(&sad, &kind)?;

        // Compute SAID (Self-Addressing IDentifier) for the sad
        let said = match sad.get("d") {
            Some(SadValue::String(d)) if !d.is_empty() => Some(d.to_string()),
            _ => match sad.get("i") {
                Some(SadValue::String(i)) if !i.is_empty() => Some(i.to_string()),
                _ => None,
            },
        };

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

/// Trait that must be implemented by types that can be parsed
pub trait Rawifiable: Sized {
    fn from_raw(raw: &[u8], smell: Option<Smellage>) -> Result<Self, KERIError>;
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
        Some(self.sad.get("t").unwrap().as_str().unwrap())
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl Rawifiable for BaseSerder {
    /// Returns an error if verification fails or if required fields are missing
    fn from_raw(raw: &[u8], smellage: Option<Smellage>) -> Result<Self, KERIError> {
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
        let said_label = get_primary_said_label(&sad);

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
                serder.said = Some(sad.get("d").unwrap().as_str().unwrap().to_string());
            }
            _ => {
                return Err(KERIError::FieldError(format!(
                    "Missing primary said field in {:?}.",
                    sad
                )));
            }
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
            set_said_placeholders(&mut sad, None);
            let raw = Self::dumps(&sad, &self.kind)?;

            let dcoder = Diger::from_qb64(said);
            let diger = Diger::from_ser_and_code(&raw, dcoder.unwrap().code())
                .map_err(|e| KERIError::from(e))?;
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
    fn pretty(&self, size: Option<usize>) -> String {
        self.base.pretty(size)
    }
    fn raw(&self) -> &[u8] {
        self.base.raw()
    }
    fn sad(&self) -> Sadder {
        self.base.sad()
    }
    fn genus(&self) -> &str {
        self.base.genus()
    }
    fn gvrsn(&self) -> &Versionage {
        self.base.gvrsn()
    }
    fn kind(&self) -> &Kinds {
        self.base.kind()
    }
    fn proto(&self) -> &str {
        self.base.proto()
    }
    fn vrsn(&self) -> &Versionage {
        self.base.vrsn()
    }
    fn size(&self) -> usize {
        self.base.size()
    }
    fn said(&self) -> Option<&str> {
        self.base.said()
    }
    fn ilk(&self) -> Option<&str> {
        self.base.ilk()
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl Rawifiable for SerderKERI {
    /// Creates a new `SerderKERI` by constructing its `BaseSerder` from raw bytes.
    fn from_raw(raw: &[u8], smell: Option<Smellage>) -> Result<Self, KERIError> {
        let base = BaseSerder::from_raw(raw, smell)?;
        Ok(Self { base })
    }
}

impl SerderKERI {
    /// Creates a new `SerderKERI` by constructing its `BaseSerder` from a sad.
    pub fn from_sad(sad: &Sadder) -> Result<Self, KERIError> {
        let base = BaseSerder::from_sad(sad)?;
        Ok(Self { base })
    }

    pub fn from_sad_and_saids(
        sad: &Sadder,
        saids: Option<HashMap<&str, String>>,
    ) -> Result<Self, KERIError> {
        let base = BaseSerder::from_init(
            None,
            Some(sad),
            Some(true),
            None,
            None,
            None,
            None,
            None,
            saids,
        )?;
        Ok(Self { base })
    }

    /// Returns true if Serder represents an establishment event
    pub fn estive(&self) -> bool {
        let t = self.base.sad.get("t").unwrap().as_str().unwrap();
        matches!(t, "icp" | "rot" | "dip" | "drt")
    }

    /// Returns key event dict property getter. Alias for .sad
    pub fn ked(&self) -> Sadder {
        self.base.sad.clone()
    }

    /// Returns qb64 of .sad["i"] identifier prefix
    pub fn pre(&self) -> Option<String> {
        Some(
            self.base
                .sad
                .get("i")
                .unwrap()
                .as_str()
                .unwrap()
                .to_string()
                .clone(),
        )
    }

    /// Returns qb64b of .pre identifier prefix as bytes
    pub fn preb(&self) -> Option<Vec<u8>> {
        self.pre().map(|pre| pre.into_bytes())
    }

    /// Number instance of sequence number
    pub fn sner(&self) -> Option<Number> {
        let num = Number::from_numh(
            self.base
                .sad
                .get("s")
                .unwrap_or(&SadValue::String("0".to_string()))
                .as_str()
                .unwrap(),
        );
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
    pub fn seals(&self) -> Option<Vec<IndexMap<String, SadValue>>> {
        match &self.base.sad.get("a") {
            Some(SadValue::Array(list)) => {
                let mut seals = Vec::new();
                for seal in list.iter() {
                    match seal {
                        SadValue::Object(seal) => seals.push(seal.clone()),
                        _ => return None,
                    }
                }
                Some(seals)
            }
            Some(SadValue::Object(map)) => {
                let mut seals = Vec::new();
                seals.push(map.clone());
                Some(seals)
            }
            _ => None,
        }
    }

    /// Traits list (config traits) from .sad["c"]
    pub fn traits(&self) -> Option<SadValue> {
        self.base.sad.get("c").cloned()
    }

    /// Tholder instance as converted from .sad['kt']
    pub fn tholder(&self) -> Option<Tholder> {
        match self.base.sad.get("kt").and_then(|v| v.as_str()) {
            Some(kt) => {
                let thold = Tholder::new(None, Some(kt.as_bytes().to_vec()), None);
                match thold {
                    Ok(thold) => Some(thold),
                    Err(e) => {
                        error!("Error parsing threshold: {}", e);
                        None
                    }
                }
            }
            None => None,
        }
    }

    /// List of qb64 keys from .sad['k']
    pub fn keys(&self) -> Option<Vec<String>> {
        match &self.base.sad.get("k") {
            Some(SadValue::Array(list)) => {
                let mut keys = Vec::new();
                for key in list.iter() {
                    match key {
                        SadValue::String(key) => keys.push(key.clone()),
                        _ => return None,
                    }
                }
                Some(keys)
            }
            _ => None,
        }
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
        match self.base.sad.get("nt").and_then(|v| v.as_str()) {
            Some(kt) => {
                let thold = Tholder::new(None, Some(kt.as_bytes().to_vec()), None);
                match thold {
                    Ok(thold) => Some(thold),
                    Err(e) => {
                        error!("Error parsing threshold: {}", e);
                        None
                    }
                }
            }
            None => None,
        }
    }

    /// Next key digests from .sad['n']
    pub fn ndigs(&self) -> Option<Vec<String>> {
        match &self.base.sad.get("n") {
            Some(SadValue::Array(list)) => {
                let mut keys = Vec::new();
                for key in list.iter() {
                    match key {
                        SadValue::String(key) => keys.push(key.clone()),
                        _ => return None,
                    }
                }
                Some(keys)
            }
            _ => None,
        }
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
        let num = Number::from_numh(
            self.base
                .sad
                .get("bt")
                .unwrap_or(&SadValue::String("0".to_string()))
                .as_str()
                .unwrap(),
        );
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
        match &self.base.sad.get("b") {
            Some(SadValue::Array(list)) => {
                let mut keys = Vec::new();
                for key in list.iter() {
                    match key {
                        SadValue::String(key) => keys.push(key.clone()),
                        _ => return None,
                    }
                }
                Some(keys)
            }
            _ => None,
        }
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
        match self.base.sad.get("p") {
            Some(sv) => match sv {
                SadValue::String(val) => Some(val.clone()),
                _ => None,
            },
            None => None,
        }
    }

    /// Prior event SAID as bytes
    pub fn priorb(&self) -> Option<Vec<u8>> {
        self.prior().map(|prior| prior.into_bytes())
    }

    /// List of backers to be cut (removed) from .sad['br']
    pub fn cuts(&self) -> Option<Vec<String>> {
        match &self.base.sad.get("br") {
            Some(SadValue::Array(list)) => {
                let mut keys = Vec::new();
                for key in list.iter() {
                    match key {
                        SadValue::String(key) => keys.push(key.clone()),
                        _ => return None,
                    }
                }
                Some(keys)
            }
            _ => None,
        }
    }

    /// List of backers to be added from .sad['ba']
    pub fn adds(&self) -> Option<Vec<String>> {
        match &self.base.sad.get("ba") {
            Some(SadValue::Array(list)) => {
                let mut keys = Vec::new();
                for key in list.iter() {
                    match key {
                        SadValue::String(key) => keys.push(key.clone()),
                        _ => return None,
                    }
                }
                Some(keys)
            }
            _ => None,
        }
    }

    /// Delegator ID prefix from .sad["di"]
    pub fn delpre(&self) -> Option<String> {
        match self.base.sad.get("di") {
            Some(sv) => match sv {
                SadValue::String(val) => Some(val.clone()),
                _ => None,
            },
            None => None,
        }
    }

    /// Delegator ID prefix as bytes
    pub fn delpreb(&self) -> Option<Vec<u8>> {
        self.delpre().map(|delpre| delpre.into_bytes())
    }

    /// Date-time-stamp from .sad["dt"]
    pub fn stamp(&self) -> Option<String> {
        match self.base.sad.get("dt") {
            Some(sv) => match sv {
                SadValue::String(val) => Some(val.clone()),
                _ => None,
            },
            None => None,
        }
    }

    /// UUID (salty nonce) from .sad["u"]
    pub fn uuid(&self) -> Option<String> {
        match self.base.sad.get("u") {
            Some(sv) => match sv {
                SadValue::String(val) => Some(val.clone()),
                _ => None,
            },
            None => None,
        }
    }

    /// Alias for .uuid property with version check
    pub fn nonce(&self) -> Option<String> {
        match self.base.sad.get("n") {
            Some(sv) => match sv {
                SadValue::String(val) => Some(val.clone()),
                _ => None,
            },
            None => None,
        }
    }

    /// Get the ilk of the event
    pub fn ilk(&self) -> Option<Ilk> {
        match self.base.sad.get("t") {
            Some(sv) => match sv {
                SadValue::String(val) => Ilk::from_str(val),
                _ => None,
            },
            None => None,
        }
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
    fn pretty(&self, size: Option<usize>) -> String {
        self.base.pretty(size)
    }
    fn raw(&self) -> &[u8] {
        self.base.raw()
    }
    fn sad(&self) -> Sadder {
        self.base.sad()
    }
    fn genus(&self) -> &str {
        self.base.genus()
    }
    fn gvrsn(&self) -> &Versionage {
        self.base.gvrsn()
    }
    fn kind(&self) -> &Kinds {
        self.base.kind()
    }
    fn proto(&self) -> &str {
        self.base.proto()
    }
    fn vrsn(&self) -> &Versionage {
        self.base.vrsn()
    }
    fn size(&self) -> usize {
        self.base.size()
    }
    fn said(&self) -> Option<&str> {
        self.base.said()
    }
    fn ilk(&self) -> Option<&str> {
        self.base.ilk()
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl SerderACDC {
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
    /// UUID (salty nonce) from .sad["u"]
    pub fn uuid(&self) -> Option<String> {
        match self.base.sad.get("u") {
            Some(sv) => match sv {
                SadValue::String(val) => Some(val.clone()),
                _ => None,
            },
            None => None,
        }
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
    pub fn issuer(&self) -> Option<String> {
        match self.base.sad.get("i") {
            Some(sv) => match sv {
                SadValue::String(val) => Some(val.clone()),
                _ => None,
            },
            None => None,
        }
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
    pub fn regi(&self) -> Option<String> {
        match self.base.sad.get("ri") {
            Some(sv) => match sv {
                SadValue::String(val) => Some(val.clone()),
                _ => None,
            },
            None => None,
        }
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
    pub fn schema(&self) -> Option<String> {
        match self.base.sad.get("s") {
            Some(sv) => match sv {
                SadValue::String(val) => Some(val.clone()),
                _ => None,
            },
            None => None,
        }
    }

    /// attrib block or SAID property getter (attribute)
    /// Optional fields return None when not present
    ///
    /// Returns:
    ///    Option<&String>: from ._sad["a"]
    pub fn attrib(&self) -> Option<IndexMap<String, SadValue>> {
        match &self.base.sad.get("a") {
            Some(SadValue::Array(_)) => None,
            Some(SadValue::Object(map)) => Some(map.clone()),
            _ => None,
        }
    }

    /// issuee property getter (issuee AID)
    /// Optional fields return None when not present
    ///
    /// Returns:
    ///    Option<String>: qb64 of .sad["a"]["i"] issuee AID
    pub fn issuee(&self) -> Option<String> {
        match &self.attrib() {
            Some(map) => match map.get("i") {
                Some(sv) => match sv {
                    SadValue::String(val) => Some(val.clone()),
                    _ => None,
                },
                None => None,
            },
            _ => None,
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
    pub fn attagg(&self) -> Option<&SadValue> {
        match &self.base.sad.get("A") {
            Some(sv) => Some(sv.clone()),
            _ => None,
        }
    }

    /// edge block property getter
    /// Optional fields return None when not present
    ///
    /// Returns:
    ///    Option<&Value>: from ._sad["e"]
    pub fn edge(&self) -> Option<IndexMap<String, SadValue>> {
        match &self.base.sad.get("e") {
            Some(SadValue::Array(_)) => None,
            Some(SadValue::Object(map)) => Some(map.clone()),
            _ => None,
        }
    }

    /// rule block property getter
    /// Optional fields return None when not present
    ///
    /// Returns:
    ///    Option<&Value>: from ._sad["r"]
    pub fn rule(&self) -> Option<IndexMap<String, SadValue>> {
        match &self.base.sad.get("r") {
            Some(SadValue::Array(_)) => None,
            Some(SadValue::Object(map)) => Some(map.clone()),
            _ => None,
        }
    }
}

impl Rawifiable for SerderACDC {
    /// Creates a new `SerderACDC` by constructing its `BaseSerder` from raw bytes.
    fn from_raw(raw: &[u8], smell: Option<Smellage>) -> Result<Self, KERIError> {
        let base = BaseSerder::from_raw(raw, smell)?;
        Ok(Self { base })
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
        skip: Option<usize>,
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
            Err(KERIError::ProtocolError(format!(
                "Unsupported protocol type = {}",
                smellage.proto
            )))
        }
    }
}

// Helper function to check if a value is iterable
fn is_iterable(value: &SadValue) -> bool {
    matches!(value, SadValue::Array(_) | SadValue::Object(_))
}

#[cfg(test)]
mod tests {
    use crate::keri::core::serdering::sad::validate;
    use crate::keri::core::serdering::{SadValue, Sadder};
    use indexmap::IndexMap;

    #[test]
    fn test_valid_icp_event() {
        let mut icp_event = IndexMap::new();

        // Add version information
        icp_event.insert("v".to_string(), SadValue::from_string("KERI10JSON00011c_"));

        // Add event type
        icp_event.insert("t".to_string(), SadValue::from_string("icp"));

        // Add SAID digest
        icp_event.insert(
            "d".to_string(),
            SadValue::from_string("EL1L56LyoKrIofnn0q7_eKmLBELDT-8rS-7wjTuELmzQ"),
        );

        // Add identifier
        icp_event.insert(
            "i".to_string(),
            SadValue::from_string("EL1L56LyoKrIofnn0q7_eKmLBELDT-8rS-7wjTuELmzQ"),
        );

        // Add sequence number
        icp_event.insert("s".to_string(), SadValue::from_string("0"));

        // Add key threshold
        icp_event.insert("kt".to_string(), SadValue::from_string("1"));

        // Add keys as array
        let keys = vec![SadValue::from_string(
            "DQbYDpQRN5cmkQ94mR69N_c98C0-SIVYEj2LM2VAGUhZ",
        )];
        icp_event.insert("k".to_string(), SadValue::from_array(keys));

        // Add next key threshold
        icp_event.insert("nt".to_string(), SadValue::from_string("1"));

        // Add next keys as array
        let next_keys = vec![SadValue::from_string(
            "EsgNZjFXMI8szR6N5eG8OsHqXxyKWrYCkP9mGkYAjS3Y",
        )];
        icp_event.insert("n".to_string(), SadValue::from_array(next_keys));

        // Add backer threshold
        icp_event.insert("bt".to_string(), SadValue::from_string("0"));

        // Add backers as empty array
        icp_event.insert("b".to_string(), SadValue::from_array(Vec::new()));

        // Add configuration traits as empty array
        icp_event.insert("c".to_string(), SadValue::from_array(Vec::new()));

        // The final result is a Sadder (IndexMap<String, SadValue>)
        let icp_event: Sadder = icp_event;

        assert!(validate(&icp_event).is_ok());
    }

    // #[test]
    // fn test_invalid_icp_event() {
    //     // Missing k field which is required for icp events
    //     let invalid_icp = Sadder {
    //         v: "KERI10JSON00011c_".to_string(),
    //         t: "icp".to_string(),
    //         d: "EL1L56LyoKrIofnn0q7_eKmLBELDT-8rS-7wjTuELmzQ".to_string(),
    //         i: Some("EL1L56LyoKrIofnn0q7_eKmLBELDT-8rS-7wjTuELmzQ".to_string()),
    //         s: Some("0".to_string()),
    //         kt: Some("1".to_string()),
    //         // k field is missing
    //         nt: Some("1".to_string()),
    //         n: Some(vec![
    //             "EsgNZjFXMI8szR6N5eG8OsHqXxyKWrYCkP9mGkYAjS3Y".to_string()
    //         ]),
    //         bt: Some("0".to_string()),
    //         b: Some(vec![]),
    //         c: Some(AttribField::StringList(vec![])),
    //         ..Default::default()
    //     };
    //
    //     assert!(invalid_icp.validate().is_err());
    // }
    //
    // #[test]
    // fn test_serder_initialization_and_verification() {
    //     // Test creating a Serder with makify=true and icp ilk
    //     let serder =
    //         BaseSerder::from_init(None, None, Some(true), None, None, None, None, None, None)
    //             .unwrap();
    //
    //     // Check the generated SAD structure
    //     let sad = serder.sad();
    //     assert_eq!(sad.t, "icp");
    //     assert_eq!(sad.s.as_ref().unwrap(), "0");
    //     assert_eq!(sad.kt.as_ref().unwrap(), "0");
    //     assert_eq!(sad.nt.as_ref().unwrap(), "0");
    //     assert_eq!(sad.bt.as_ref().unwrap(), "0");
    //     assert!(sad.k.as_ref().unwrap().is_empty());
    //     assert!(sad.n.as_ref().unwrap().is_empty());
    //     assert!(sad.b.as_ref().unwrap().is_empty());
    //     assert!(sad.c.as_ref().unwrap().is_empty());
    //
    //     // In Python there's an assert for 'a' field, assuming it exists in Rust as well
    //     match &sad.a {
    //         Some(AttribField::StringList(list)) => assert!(list.is_empty()),
    //         Some(AttribField::StringMap(map)) => assert!(map.is_empty()),
    //         None => panic!("Expected 'a' field to exist but be empty"),
    //     }
    //
    //     // Verify the SAID is consistent
    //     assert_eq!(sad.d, sad.i.clone().unwrap());
    //
    //     // Get raw bytes and verify they match the expected pattern
    //     let raw = serder.raw();
    //     assert!(raw.starts_with(b"{\"v\":\"KERI10JSON"));
    //     // assert!(raw.contains(b"\"t\":\"icp\""));
    //
    //     // Verify other properties
    //     // assert!(serder.verify().is_ok());
    //     assert_eq!(serder.ilk().unwrap(), "icp");
    //
    //     // Store values for reconstruction tests
    //     let sad_clone = serder.sad().clone();
    //     let raw_clone = serder.raw();
    //     let said = serder.said().clone();
    //     let size = serder.size();
    //
    //     // Test reconstruction from SAD
    //     let serder_from_sad = SerderKERI::from_sad(&sad_clone).unwrap();
    //     assert_eq!(serder_from_sad.raw(), raw_clone);
    //     assert_eq!(serder_from_sad.sad().d, sad.d);
    //     assert_eq!(serder_from_sad.proto(), "KERI");
    //     assert_eq!(serder_from_sad.vrsn(), &VRSN_1_0);
    //     assert_eq!(serder_from_sad.size(), size);
    //     assert_eq!(serder_from_sad.kind(), &Kinds::Json);
    //     assert_eq!(serder_from_sad.said(), said);
    //     assert_eq!(serder_from_sad.ilk().unwrap(), Ilk::Icp);
    //
    //     // Test reconstruction from raw bytes
    //     let serder_from_raw = SerderKERI::from_raw(&raw_clone, None).unwrap();
    //     assert_eq!(serder_from_raw.raw(), raw_clone);
    //
    //     // Check that SAD matches between original and reconstructed from raw
    //     let regenerated_sad = serder_from_raw.sad();
    //     assert_eq!(regenerated_sad.v, sad.v);
    //     assert_eq!(regenerated_sad.t, sad.t);
    //     assert_eq!(regenerated_sad.d, sad.d);
    //     assert_eq!(regenerated_sad.i, sad.i);
    //
    //     // Additional verification
    //     assert_eq!(serder_from_raw.proto(), "KERI");
    //     assert_eq!(serder_from_raw.vrsn(), &VRSN_1_0);
    //     assert_eq!(serder_from_raw.size(), size);
    //     assert_eq!(serder_from_raw.kind(), &Kinds::Json);
    //     assert_eq!(serder_from_raw.said(), said);
    //     assert_eq!(serder_from_raw.ilk().unwrap(), Ilk::Icp);
    //
    //     // Test creating a Serder with makify=true and icp ilk
    //     let mut sad = Sadder::default();
    //     sad.i = Some("DKxy2sgzfplyr-tgwIxS19f2OchFHtLwPWD3v4oYimBx".to_string());
    //     let serder = BaseSerder::from_init(
    //         None,
    //         Some(&sad),
    //         Some(true),
    //         None,
    //         None,
    //         None,
    //         None,
    //         None,
    //         None,
    //     )
    //     .unwrap();
    //     assert_eq!(serder.sad().i, sad.i);
    //     assert_eq!(
    //         serder.sad().d,
    //         "EIXK39EgyxshefoCdSpKCkG5FR9s405YI4FAHDvAqO_R"
    //     );
    // }
}
