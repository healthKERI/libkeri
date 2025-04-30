use crate::cesr::{dig_dex, get_sizes, mtr_dex, BaseMatter};
use crate::keri::{Ilk, Ilks, KERIError, Kinds, Said};
use crate::Matter;
use indexmap::IndexMap;
use serde::ser::{SerializeMap, SerializeSeq};
use serde::{de, ser};
use serde::{Deserialize, Serialize};
use serde::{Deserializer, Serializer};
use serde_json::Number;
use std::collections::HashMap;
use std::fmt;

#[derive(Clone)]
pub enum SadValue {
    Bool(bool),
    Number(Number),
    String(String),
    Array(Vec<SadValue>),
    Object(IndexMap<String, SadValue>),
}

pub type Sadder = IndexMap<String, SadValue>;

impl SadValue {
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

    // Type checking methods
    pub fn is_array(&self) -> bool {
        matches!(self, SadValue::Array(_))
    }

    pub fn is_object(&self) -> bool {
        matches!(self, SadValue::Object(_))
    }

    pub fn is_string(&self) -> bool {
        matches!(self, SadValue::String(_))
    }

    pub fn is_number(&self) -> bool {
        matches!(self, SadValue::Number(_))
    }

    pub fn is_bool(&self) -> bool {
        matches!(self, SadValue::Bool(_))
    }

    pub fn is_i64(&self) -> bool {
        match self {
            SadValue::Number(n) => n.is_i64(),
            _ => false,
        }
    }

    pub fn is_u64(&self) -> bool {
        match self {
            SadValue::Number(n) => n.is_u64(),
            _ => false,
        }
    }

    pub fn is_f64(&self) -> bool {
        match self {
            SadValue::Number(n) => n.is_f64(),
            _ => false,
        }
    }

    // Value extraction methods
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            SadValue::Bool(b) => Some(*b),
            _ => None,
        }
    }

    pub fn as_i64(&self) -> Option<i64> {
        match self {
            SadValue::Number(n) => n.as_i64(),
            _ => None,
        }
    }

    pub fn as_u64(&self) -> Option<u64> {
        match self {
            SadValue::Number(n) => n.as_u64(),
            _ => None,
        }
    }

    pub fn as_f64(&self) -> Option<f64> {
        match self {
            SadValue::Number(n) => n.as_f64(),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            SadValue::String(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&Vec<SadValue>> {
        match self {
            SadValue::Array(a) => Some(a),
            _ => None,
        }
    }

    pub fn as_object(&self) -> Option<&IndexMap<String, SadValue>> {
        match self {
            SadValue::Object(o) => Some(o),
            _ => None,
        }
    }

    // Mutable access methods
    pub fn as_array_mut(&mut self) -> Option<&mut Vec<SadValue>> {
        match self {
            SadValue::Array(a) => Some(a),
            _ => None,
        }
    }

    pub fn as_object_mut(&mut self) -> Option<&mut IndexMap<String, SadValue>> {
        match self {
            SadValue::Object(o) => Some(o),
            _ => None,
        }
    }

    // Take ownership methods
    pub fn take_array(self) -> Option<Vec<SadValue>> {
        match self {
            SadValue::Array(a) => Some(a),
            _ => None,
        }
    }

    pub fn take_object(self) -> Option<IndexMap<String, SadValue>> {
        match self {
            SadValue::Object(o) => Some(o),
            _ => None,
        }
    }

    pub fn take_string(self) -> Option<String> {
        match self {
            SadValue::String(s) => Some(s),
            _ => None,
        }
    }

    pub fn take_bool(self) -> Option<bool> {
        match self {
            SadValue::Bool(b) => Some(b),
            _ => None,
        }
    }

    pub fn take_number(self) -> Option<Number> {
        match self {
            SadValue::Number(n) => Some(n),
            _ => None,
        }
    }

    // Conversion methods - from primitives to SadValue
    pub fn from_bool(b: bool) -> Self {
        SadValue::Bool(b)
    }

    pub fn from_i64(i: i64) -> Self {
        SadValue::Number(Number::from(i))
    }

    pub fn from_u64(u: u64) -> Self {
        SadValue::Number(Number::from(u))
    }

    pub fn from_f64(f: f64) -> Result<Self, String> {
        match Number::from_f64(f) {
            Some(n) => Ok(SadValue::Number(n)),
            None => Err("Invalid float value".to_string()),
        }
    }

    pub fn from_string<S: Into<String>>(s: S) -> Self {
        SadValue::String(s.into())
    }

    pub fn from_array<A: IntoIterator<Item = SadValue>>(a: A) -> Self {
        SadValue::Array(a.into_iter().collect())
    }

    pub fn from_object<O: IntoIterator<Item = (String, SadValue)>>(o: O) -> Self {
        SadValue::Object(o.into_iter().collect())
    }

    // Accessor methods for nested values using paths
    pub fn pointer(&self, path: &str) -> Option<&SadValue> {
        if path.is_empty() || path == "/" {
            return Some(self);
        }

        if !path.starts_with('/') {
            return None;
        }

        let mut target = self;
        for token in path[1..].split('/') {
            let token = token.replace("~1", "/").replace("~0", "~");

            match target {
                SadValue::Object(map) => {
                    target = map.get(&token)?;
                }
                SadValue::Array(vec) => {
                    if let Ok(index) = token.parse::<usize>() {
                        target = vec.get(index)?;
                    } else {
                        return None;
                    }
                }
                _ => return None,
            }
        }

        Some(target)
    }

    pub fn pointer_mut(&mut self, path: &str) -> Option<&mut SadValue> {
        if path.is_empty() || path == "/" {
            return Some(self);
        }

        if !path.starts_with('/') {
            return None;
        }

        let mut target = self;
        let tokens: Vec<_> = path[1..].split('/').collect();
        let (last_token, path_tokens) = tokens.split_last()?;
        let last_token = last_token.replace("~1", "/").replace("~0", "~");

        for token in path_tokens {
            let token = token.replace("~1", "/").replace("~0", "~");

            target = match target {
                SadValue::Object(map) => map.get_mut(&token)?,
                SadValue::Array(vec) => {
                    if let Ok(index) = token.parse::<usize>() {
                        vec.get_mut(index)?
                    } else {
                        return None;
                    }
                }
                _ => return None,
            };
        }

        match target {
            SadValue::Object(map) => map.get_mut(&last_token),
            SadValue::Array(vec) => {
                if let Ok(index) = last_token.parse::<usize>() {
                    vec.get_mut(index)
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    // Index methods
    pub fn get<I: Index>(&self, index: I) -> Option<&SadValue> {
        index.index_into(self)
    }

    pub fn get_mut<I: Index>(&mut self, index: I) -> Option<&mut SadValue> {
        index.index_into_mut(self)
    }
}

// Implement the Index trait for accessing elements more easily
pub trait Index {
    fn index_into(self, target: &SadValue) -> Option<&SadValue>;
    fn index_into_mut(self, target: &mut SadValue) -> Option<&mut SadValue>;
}

impl Index for usize {
    fn index_into(self, target: &SadValue) -> Option<&SadValue> {
        match target {
            SadValue::Array(arr) => arr.get(self),
            _ => None,
        }
    }

    fn index_into_mut(self, target: &mut SadValue) -> Option<&mut SadValue> {
        match target {
            SadValue::Array(arr) => arr.get_mut(self),
            _ => None,
        }
    }
}

impl Index for &str {
    fn index_into(self, target: &SadValue) -> Option<&SadValue> {
        match target {
            SadValue::Object(map) => map.get(self),
            _ => None,
        }
    }

    fn index_into_mut(self, target: &mut SadValue) -> Option<&mut SadValue> {
        match target {
            SadValue::Object(map) => map.get_mut(self),
            _ => None,
        }
    }
}

impl Index for String {
    fn index_into(self, target: &SadValue) -> Option<&SadValue> {
        self.as_str().index_into(target)
    }

    fn index_into_mut(self, target: &mut SadValue) -> Option<&mut SadValue> {
        self.as_str().index_into_mut(target)
    }
}

impl Index for &String {
    fn index_into(self, target: &SadValue) -> Option<&SadValue> {
        self.as_str().index_into(target)
    }

    fn index_into_mut(self, target: &mut SadValue) -> Option<&mut SadValue> {
        self.as_str().index_into_mut(target)
    }
}

// Implement equality between SadValue instances
impl PartialEq for SadValue {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (SadValue::Bool(a), SadValue::Bool(b)) => a == b,
            (SadValue::Number(a), SadValue::Number(b)) => a == b,
            (SadValue::String(a), SadValue::String(b)) => a == b,
            (SadValue::Array(a), SadValue::Array(b)) => a == b,
            (SadValue::Object(a), SadValue::Object(b)) => a == b,
            _ => false,
        }
    }
}

impl Eq for SadValue {}

// Implement Debug trait for better logging and debugging
impl fmt::Debug for SadValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SadValue::Bool(b) => write!(f, "Bool({})", b),
            SadValue::Number(n) => write!(f, "Number({})", n),
            SadValue::String(s) => write!(f, "String({})", s),
            SadValue::Array(a) => f.debug_list().entries(a).finish(),
            SadValue::Object(o) => f.debug_map().entries(o).finish(),
        }
    }
}

// Add Serialize implementation for SadValue
impl Serialize for SadValue {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            SadValue::Bool(b) => serializer.serialize_bool(*b),
            SadValue::Number(n) => {
                if let Some(v) = n.as_i64() {
                    serializer.serialize_i64(v)
                } else if let Some(v) = n.as_u64() {
                    serializer.serialize_u64(v)
                } else if let Some(v) = n.as_f64() {
                    serializer.serialize_f64(v)
                } else {
                    // Should not happen with the Number implementation
                    Err(ser::Error::custom("Number cannot be serialized"))
                }
            }
            SadValue::String(s) => serializer.serialize_str(s),
            SadValue::Array(a) => {
                let mut seq = serializer.serialize_seq(Some(a.len()))?;
                for element in a {
                    seq.serialize_element(element)?;
                }
                seq.end()
            }
            SadValue::Object(o) => {
                let mut map = serializer.serialize_map(Some(o.len()))?;
                for (k, v) in o {
                    map.serialize_entry(k, v)?;
                }
                map.end()
            }
        }
    }
}

// Define a visitor for SadValue deserialization
struct SadVisitor;

impl<'de> de::Visitor<'de> for SadVisitor {
    type Value = SadValue;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a valid JSON value")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(SadValue::Bool(value))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(SadValue::Number(serde_json::Number::from(value)))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(SadValue::Number(serde_json::Number::from(value)))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        match Number::from_f64(value) {
            Some(n) => Ok(SadValue::Number(n)),
            None => Err(E::custom(format!("Invalid float value: {}", value))),
        }
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(SadValue::String(value.to_owned()))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(SadValue::String(value))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        // SadValue doesn't have a Null variant,
        // so we represent null as a special Boolean value
        // An alternative could be to return a default empty value
        Ok(SadValue::Bool(false))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        // Same as visit_none for SadValue
        Ok(SadValue::Bool(false))
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: de::SeqAccess<'de>,
    {
        let mut values = Vec::new();

        while let Some(value) = seq.next_element()? {
            values.push(value);
        }

        Ok(SadValue::Array(values))
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: de::MapAccess<'de>,
    {
        let mut obj = IndexMap::new();

        while let Some((key, value)) = map.next_entry()? {
            obj.insert(key, value);
        }

        Ok(SadValue::Object(obj))
    }
}

// Add Deserialize implementation for SadValue
impl<'de> Deserialize<'de> for SadValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(SadVisitor)
    }
}

/// Sets the SAID fields with dummy placeholders of the appropriate length in a Sadd map
///
/// # Arguments
/// * `sad` - The Sadd map to modify
/// * `saids` - Optional map of label to digest type code overrides
///
/// This function sets the digestive fields with proper length placeholders
/// based on the digest type
pub fn set_said_placeholders(sad: &mut Sadder, saids: Option<HashMap<&str, String>>) {
    // Define the default SAIDs mapping
    let mut _saids: HashMap<&str, String> = HashMap::new();

    // Get the ilk type
    let ilk = if let Some(SadValue::String(t)) = sad.get("t") {
        t.as_str()
    } else {
        return; // No ilk type, can't set placeholders
    };

    // Set up the defaults based on the ilk type
    match ilk {
        "icp" | "dip" => {
            _saids.insert("d", mtr_dex::BLAKE3_256.to_string()); // Blake3_256

            if let Some(SadValue::String(i)) = sad.get("i") {
                if !i.is_empty() {
                    match BaseMatter::from_qb64(i) {
                        Ok(mtr) => {
                            let code = String::from(mtr.code());
                            if dig_dex::TUPLE.contains(&code.as_str()) {
                                _saids.insert("i", code);
                            }
                        }
                        Err(_) => {
                            _saids.insert("i", mtr_dex::BLAKE3_256.to_string());
                            // Blake3_256
                        }
                    }
                } else {
                    _saids.insert("i", mtr_dex::BLAKE3_256.to_string()); // Blake3_256
                }
            } else {
                _saids.insert("i", mtr_dex::BLAKE3_256.to_string()); // Blake3_256
            }
        }
        "rot" | "drt" | "vrt" | "rev" | "brv" => {
            _saids.insert("d", mtr_dex::BLAKE3_256.to_string()); // Blake3_256
        }
        "ixn" | "rct" => {
            _saids.insert("d", mtr_dex::BLAKE3_256.to_string()); // Blake3_256
        }
        "qry" | "rpy" | "pro" | "bar" | "exn" => {
            _saids.insert("d", mtr_dex::BLAKE3_256.to_string()); // Blake3_256
        }
        "vcp" => {
            _saids.insert("d", mtr_dex::BLAKE3_256.to_string()); // Blake3_256
            _saids.insert("i", mtr_dex::BLAKE3_256.to_string()); // Blake3_256
        }
        "iss" => {
            _saids.insert("d", mtr_dex::BLAKE3_256.to_string()); // Blake3_256
        }
        "bis" => {
            _saids.insert("d", mtr_dex::BLAKE3_256.to_string()); // Blake3_256
        }
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
            if let Some(fs) = size.fs {
                // Create a properly sized dummy string
                let dummy_value = dummy.repeat(fs as usize);

                // Set the appropriate field based on the label
                match *label {
                    "d" => {
                        sad.insert("d".to_string(), SadValue::String(dummy_value));
                    }
                    "i" => {
                        sad.insert("i".to_string(), SadValue::String(dummy_value));
                    }
                    // Add other SAID fields as needed
                    _ => {} // Ignore unknown labels
                }
            }
        }
    }
}

/// Creates a Sadd with type-specific field defaults based on an existing Sadd
///
/// # Arguments
/// * `ilk` - The event type (Ilk)
/// * `orig` - The original Sadd object to preserve values from
///
/// # Returns
/// A new Sadd instance with appropriate defaults for the given ilk,
/// preserving any existing values from the original
pub fn default_with_type(ilk: Ilk, orig: &Sadder) -> Sadder {
    let mut sad = Sadder::new();

    // Determine the actual ilk to use
    let ilk_str = if let Some(SadValue::String(t)) = orig.get("t") {
        if !t.is_empty() {
            t.clone()
        } else {
            ilk.as_str().to_string()
        }
    } else {
        ilk.as_str().to_string()
    };

    // Preserve version if already set
    if let Some(SadValue::String(v)) = orig.get("v") {
        if !v.is_empty() {
            sad.insert("v".to_string(), SadValue::String(v.clone()));
        } else {
            sad.insert("v".to_string(), SadValue::String("".to_string()));
        }
    } else {
        sad.insert("v".to_string(), SadValue::String("".to_string()));
    }

    // Set the type field
    sad.insert("t".to_string(), SadValue::String(ilk_str.clone()));

    // Preserve digest if already set
    if let Some(SadValue::String(d)) = orig.get("d") {
        if !d.is_empty() {
            sad.insert("d".to_string(), SadValue::String(d.clone()));
        } else {
            sad.insert("d".to_string(), SadValue::String("".to_string()));
        }
    } else {
        sad.insert("d".to_string(), SadValue::String("".to_string()));
    }

    // Helper function to get a string value or empty string default
    let get_string_or_empty = |map: &Sadder, key: &str| -> SadValue {
        if let Some(SadValue::String(s)) = map.get(key) {
            SadValue::String(s.clone())
        } else {
            SadValue::String("".to_string())
        }
    };

    // Helper function to get a string value with default
    let get_string_or_default = |map: &Sadder, key: &str, default: &str| -> SadValue {
        if let Some(SadValue::String(s)) = map.get(key) {
            SadValue::String(s.clone())
        } else {
            SadValue::String(default.to_string())
        }
    };

    // Helper function to get a string value with default
    let get_string_or_number_default = |map: &Sadder, key: &str, default: &str| -> SadValue {
        if let Some(SadValue::String(s)) = map.get(key) {
            SadValue::String(s.clone())
        } else if let Some(SadValue::Number(n)) = map.get(key) {
            SadValue::Number(n.clone())
        } else {
            SadValue::String(default.to_string())
        }
    };

    // Helper function to get an array or empty array
    let get_array_or_empty = |map: &Sadder, key: &str| -> SadValue {
        if let Some(SadValue::Array(a)) = map.get(key) {
            SadValue::Array(a.clone())
        } else {
            SadValue::Array(vec![])
        }
    };

    // Helper function to get an empty object
    let get_object_or_empty = |map: &Sadder, key: &str| -> SadValue {
        if let Some(SadValue::Object(o)) = map.get(key) {
            SadValue::Object(o.clone())
        } else {
            SadValue::Object(IndexMap::new())
        }
    };

    // Apply type-specific defaults based on ilk
    match ilk_str.as_str() {
        "icp" => {
            sad.insert("i".to_string(), get_string_or_empty(orig, "i"));
            sad.insert("s".to_string(), get_string_or_default(orig, "s", "0"));
            sad.insert(
                "kt".to_string(),
                get_string_or_number_default(orig, "kt", "0"),
            );
            sad.insert("k".to_string(), get_array_or_empty(orig, "k"));
            sad.insert(
                "nt".to_string(),
                get_string_or_number_default(orig, "nt", "0"),
            );
            sad.insert("n".to_string(), get_array_or_empty(orig, "n"));
            sad.insert(
                "bt".to_string(),
                get_string_or_number_default(orig, "bt", "0"),
            );
            sad.insert("b".to_string(), get_array_or_empty(orig, "b"));
            sad.insert("c".to_string(), get_array_or_empty(orig, "c"));
            sad.insert("a".to_string(), get_array_or_empty(orig, "a"));
        }
        "rot" => {
            sad.insert("i".to_string(), get_string_or_empty(orig, "i"));
            sad.insert("s".to_string(), get_string_or_default(orig, "s", "0"));
            sad.insert("p".to_string(), get_string_or_empty(orig, "p"));
            sad.insert(
                "kt".to_string(),
                get_string_or_number_default(orig, "kt", "0"),
            );
            sad.insert("k".to_string(), get_array_or_empty(orig, "k"));
            sad.insert(
                "nt".to_string(),
                get_string_or_number_default(orig, "nt", "0"),
            );
            sad.insert("n".to_string(), get_array_or_empty(orig, "n"));
            sad.insert(
                "bt".to_string(),
                get_string_or_number_default(orig, "bt", "0"),
            );
            sad.insert("br".to_string(), get_array_or_empty(orig, "br"));
            sad.insert("ba".to_string(), get_array_or_empty(orig, "ba"));
            sad.insert("a".to_string(), get_array_or_empty(orig, "a"));
        }
        "ixn" => {
            sad.insert("i".to_string(), get_string_or_empty(orig, "i"));
            sad.insert("s".to_string(), get_string_or_default(orig, "s", "0"));
            sad.insert("p".to_string(), get_string_or_empty(orig, "p"));
            sad.insert("a".to_string(), get_array_or_empty(orig, "a"));
        }
        "dip" => {
            sad.insert("i".to_string(), get_string_or_empty(orig, "i"));
            sad.insert("s".to_string(), get_string_or_default(orig, "s", "0"));
            sad.insert(
                "kt".to_string(),
                get_string_or_number_default(orig, "kt", "0"),
            );
            sad.insert("k".to_string(), get_array_or_empty(orig, "k"));
            sad.insert(
                "nt".to_string(),
                get_string_or_number_default(orig, "nt", "0"),
            );
            sad.insert("n".to_string(), get_array_or_empty(orig, "n"));
            sad.insert(
                "bt".to_string(),
                get_string_or_number_default(orig, "bt", "0"),
            );
            sad.insert("b".to_string(), get_array_or_empty(orig, "b"));
            sad.insert("c".to_string(), get_array_or_empty(orig, "c"));
            sad.insert("a".to_string(), get_array_or_empty(orig, "a"));
            sad.insert("di".to_string(), get_string_or_empty(orig, "di"));
        }
        "drt" => {
            sad.insert("i".to_string(), get_string_or_empty(orig, "i"));
            sad.insert("s".to_string(), get_string_or_default(orig, "s", "0"));
            sad.insert("p".to_string(), get_string_or_empty(orig, "p"));
            sad.insert(
                "kt".to_string(),
                get_string_or_number_default(orig, "kt", "0"),
            );
            sad.insert("k".to_string(), get_array_or_empty(orig, "k"));
            sad.insert(
                "nt".to_string(),
                get_string_or_number_default(orig, "nt", "0"),
            );
            sad.insert("n".to_string(), get_array_or_empty(orig, "n"));
            sad.insert(
                "bt".to_string(),
                get_string_or_number_default(orig, "bt", "0"),
            );
            sad.insert("br".to_string(), get_array_or_empty(orig, "br"));
            sad.insert("ba".to_string(), get_array_or_empty(orig, "ba"));
            sad.insert("a".to_string(), get_array_or_empty(orig, "a"));
        }
        "rct" => {
            sad.insert("i".to_string(), get_string_or_empty(orig, "i"));
            sad.insert("s".to_string(), get_string_or_default(orig, "s", "0"));
        }
        "qry" => {
            sad.insert("dt".to_string(), get_string_or_empty(orig, "dt"));
            sad.insert("r".to_string(), get_string_or_empty(orig, "r"));
            sad.insert("rr".to_string(), get_string_or_empty(orig, "rr"));
            sad.insert("q".to_string(), get_object_or_empty(orig, "q"));
        }
        "rpy" => {
            sad.insert("dt".to_string(), get_string_or_empty(orig, "dt"));
            sad.insert("r".to_string(), get_string_or_empty(orig, "r"));
            sad.insert("a".to_string(), get_array_or_empty(orig, "a"));
        }
        "pro" => {
            sad.insert("dt".to_string(), get_string_or_empty(orig, "dt"));
            sad.insert("r".to_string(), get_string_or_empty(orig, "r"));
            sad.insert("rr".to_string(), get_string_or_empty(orig, "rr"));
            sad.insert("q".to_string(), get_object_or_empty(orig, "q"));
        }
        "bar" => {
            sad.insert("dt".to_string(), get_string_or_empty(orig, "dt"));
            sad.insert("r".to_string(), get_string_or_empty(orig, "r"));
            sad.insert("a".to_string(), get_array_or_empty(orig, "a"));
        }
        "exn" => {
            sad.insert("i".to_string(), get_string_or_empty(orig, "i"));
            sad.insert("rp".to_string(), get_string_or_empty(orig, "rp"));
            sad.insert("p".to_string(), get_string_or_empty(orig, "p"));
            sad.insert("dt".to_string(), get_string_or_empty(orig, "dt"));
            sad.insert("r".to_string(), get_string_or_empty(orig, "r"));
            sad.insert("q".to_string(), get_object_or_empty(orig, "q"));
            sad.insert("a".to_string(), get_array_or_empty(orig, "a"));
            sad.insert("e".to_string(), get_object_or_empty(orig, "e"));
        }
        "vcp" => {
            sad.insert("i".to_string(), get_string_or_empty(orig, "i"));
            sad.insert("ii".to_string(), get_string_or_empty(orig, "ii"));
            sad.insert("s".to_string(), get_string_or_default(orig, "s", "0"));
            sad.insert("c".to_string(), get_array_or_empty(orig, "c"));
            sad.insert("bt".to_string(), get_string_or_default(orig, "bt", "0"));
            sad.insert("b".to_string(), get_array_or_empty(orig, "b"));
        }
        "vrt" => {
            sad.insert("i".to_string(), get_string_or_empty(orig, "i"));
            sad.insert("p".to_string(), get_string_or_empty(orig, "p"));
            sad.insert("s".to_string(), get_string_or_default(orig, "s", "0"));
            sad.insert(
                "bt".to_string(),
                get_string_or_number_default(orig, "bt", "0"),
            );
            sad.insert("br".to_string(), get_array_or_empty(orig, "br"));
            sad.insert("ba".to_string(), get_array_or_empty(orig, "ba"));
        }
        "iss" => {
            sad.insert("i".to_string(), get_string_or_empty(orig, "i"));
            sad.insert("s".to_string(), get_string_or_default(orig, "s", "0"));
            sad.insert("ri".to_string(), get_string_or_empty(orig, "ri"));
            sad.insert("dt".to_string(), get_string_or_empty(orig, "dt"));
        }
        "rev" => {
            sad.insert("i".to_string(), get_string_or_empty(orig, "i"));
            sad.insert("s".to_string(), get_string_or_default(orig, "s", "0"));
            sad.insert("ri".to_string(), get_string_or_empty(orig, "ri"));
            sad.insert("p".to_string(), get_string_or_empty(orig, "p"));
            sad.insert("dt".to_string(), get_string_or_empty(orig, "dt"));
        }
        "bis" => {
            sad.insert("i".to_string(), get_string_or_empty(orig, "i"));
            sad.insert("ii".to_string(), get_string_or_empty(orig, "ii"));
            sad.insert("s".to_string(), get_string_or_default(orig, "s", "0"));
            sad.insert("r".to_string(), get_object_or_empty(orig, "rules"));
            sad.insert("dt".to_string(), get_string_or_empty(orig, "dt"));
        }
        "brv" => {
            sad.insert("i".to_string(), get_string_or_empty(orig, "i"));
            sad.insert("s".to_string(), get_string_or_default(orig, "s", "0"));
            sad.insert("p".to_string(), get_string_or_empty(orig, "p"));
            sad.insert("r".to_string(), get_object_or_empty(orig, "rules"));
            sad.insert("dt".to_string(), get_string_or_empty(orig, "dt"));
        }
        // Default case for unknown ilk types
        _ => {
            // Keep the base defaults initialized above
        }
    }

    sad
}

/// Create a validation schema for the different event types
pub fn build_validation_schema() -> HashMap<Ilk, Vec<&'static str>> {
    let mut schema = HashMap::new();

    // For each ilk, define the required fields (those that must be present)
    schema.insert(
        Ilk::Icp,
        vec![
            "v", "t", "d", "i", "s", "kt", "k", "nt", "n", "bt", "b", "c",
        ],
    );
    schema.insert(
        Ilk::Rot,
        vec![
            "v", "t", "d", "i", "s", "p", "kt", "k", "nt", "n", "bt", "br", "ba",
        ],
    );
    schema.insert(Ilk::Ixn, vec!["v", "t", "d", "i", "s", "p"]);
    schema.insert(
        Ilk::Dip,
        vec![
            "v", "t", "d", "i", "s", "kt", "k", "nt", "n", "bt", "b", "c", "di",
        ],
    );
    schema.insert(
        Ilk::Drt,
        vec![
            "v", "t", "d", "i", "s", "p", "kt", "k", "nt", "n", "bt", "br", "ba",
        ],
    );
    schema.insert(Ilk::Rct, vec!["v", "t", "d", "i", "s"]);
    schema.insert(Ilk::Qry, vec!["v", "t", "d", "dt", "r", "rr", "q"]);
    schema.insert(Ilk::Rpy, vec!["v", "t", "d", "dt", "r", "a"]);
    schema.insert(Ilk::Pro, vec!["v", "t", "d", "dt", "r", "rr", "q"]);
    schema.insert(Ilk::Bar, vec!["v", "t", "d", "dt", "r", "a"]);
    schema.insert(
        Ilk::Exn,
        vec!["v", "t", "d", "i", "rp", "p", "dt", "r", "q", "a", "e"],
    );
    schema.insert(
        Ilk::Vcp,
        vec!["v", "t", "d", "i", "ii", "s", "c", "bt", "b", "n"],
    );
    schema.insert(
        Ilk::Vrt,
        vec!["v", "t", "d", "i", "p", "s", "bt", "br", "ba"],
    );
    schema.insert(Ilk::Iss, vec!["v", "t", "d", "i", "s", "ri", "dt"]);
    schema.insert(Ilk::Rev, vec!["v", "t", "d", "i", "s", "ri", "p", "dt"]);
    schema.insert(Ilk::Bis, vec!["v", "t", "d", "i", "ii", "s", "ra", "dt"]);
    schema.insert(Ilk::Brv, vec!["v", "t", "d", "i", "s", "p", "ra", "dt"]);

    schema
}

/// Validates a Sadd map against the schema requirements
///
/// # Arguments
/// * `sad` - The Sadd map to validate
///
/// # Returns
/// * `Ok(())` if validation passes
/// * `Err(KERIError)` with a detailed error message if validation fails
pub fn validate(sad: &Sadder) -> Result<(), KERIError> {
    // Get the ilk value which determines the schema to use
    let ilk_str = match sad.get("t") {
        Some(SadValue::String(t)) => t.as_str(),
        _ => {
            return Err(KERIError::ValidationError(
                "Missing or invalid 't' field".to_string(),
            ))
        }
    };

    // Try to convert string ilk to Ilk enum
    let ilk = match Ilk::from_str(ilk_str) {
        Some(ilk) => ilk,
        None => {
            return Err(KERIError::ValidationError(format!(
                "Invalid ilk type: {}",
                ilk_str
            )))
        }
    };

    // Get the validation schema for this ilk
    let schema = build_validation_schema();
    let fields = match schema.get(&ilk) {
        Some(fields) => fields,
        None => {
            return Err(KERIError::ValidationError(format!(
                "No schema found for ilk: {}",
                ilk_str
            )))
        }
    };

    // Check that all required fields are present and have appropriate values
    for &field in fields {
        match field {
            "v" => {
                // Version is required and must not be empty
                if !has_non_empty_string(sad, "v") {
                    return Err(KERIError::ValidationError(
                        "Missing or empty version field 'v'".to_string(),
                    ));
                }
            }
            "t" => {
                // Type is already validated above
            }
            "d" => {
                // Digest is required and must not be empty
                if !has_non_empty_string(sad, "d") {
                    return Err(KERIError::ValidationError(
                        "Missing or empty digest field 'd'".to_string(),
                    ));
                }
            }
            "i" => {
                // Identifier is required for most events
                if !has_non_empty_string(sad, "i") {
                    return Err(KERIError::ValidationError(
                        "Missing or empty identifier field 'i'".to_string(),
                    ));
                }
            }
            "s" => {
                // Sequence number is required for key events
                if !has_field(sad, "s") {
                    return Err(KERIError::ValidationError(
                        "Missing sequence number field 's'".to_string(),
                    ));
                }

                // Validate as number string or parse as integer
                if let Some(SadValue::String(s)) = sad.get("s") {
                    if s.parse::<u64>().is_err() {
                        return Err(KERIError::ValidationError(format!(
                            "Invalid sequence number '{}': must be a non-negative integer",
                            s
                        )));
                    }
                } else {
                    return Err(KERIError::ValidationError(
                        "Sequence number 's' must be a string value".to_string(),
                    ));
                }
            }
            "p" => {
                // Prior event digest is required for rotation and interaction events
                if matches!(
                    ilk,
                    Ilk::Rot | Ilk::Ixn | Ilk::Drt | Ilk::Vrt | Ilk::Rev | Ilk::Brv
                ) && !has_non_empty_string(sad, "p")
                {
                    return Err(KERIError::ValidationError(
                        "Missing or empty prior digest field 'p'".to_string(),
                    ));
                }
            }
            "kt" => {
                // Key threshold is required for inception and rotation events
                if matches!(ilk, Ilk::Icp | Ilk::Rot | Ilk::Dip | Ilk::Drt) && !has_field(sad, "kt")
                {
                    return Err(KERIError::ValidationError(
                        "Missing key threshold field 'kt'".to_string(),
                    ));
                }

                // Validate as threshold string or parse as integer
                if let Some(SadValue::String(kt)) = sad.get("kt") {
                    if kt.parse::<u64>().is_err() {
                        return Err(KERIError::ValidationError(format!(
                            "Invalid key threshold '{}': must be a non-negative integer",
                            kt
                        )));
                    }
                } else if has_field(sad, "kt") {
                    return Err(KERIError::ValidationError(
                        "Key threshold 'kt' must be a string value".to_string(),
                    ));
                }
            }
            "k" => {
                // Keys are required for inception and rotation events
                if matches!(ilk, Ilk::Icp | Ilk::Rot | Ilk::Dip | Ilk::Drt) {
                    // Must be an array of strings
                    if !has_string_array(sad, "k") {
                        return Err(KERIError::ValidationError(
                            "Missing or invalid keys field 'k': must be an array of strings"
                                .to_string(),
                        ));
                    }

                    // Validate each key is a non-empty string
                    if let Some(SadValue::Array(keys)) = sad.get("k") {
                        for (i, key) in keys.iter().enumerate() {
                            if let Some(key_str) = key.as_str() {
                                if key_str.is_empty() {
                                    return Err(KERIError::ValidationError(format!(
                                        "Empty key at index {} in 'k'",
                                        i
                                    )));
                                }
                            } else {
                                return Err(KERIError::ValidationError(format!(
                                    "Non-string key at index {} in 'k'",
                                    i
                                )));
                            }
                        }
                    }
                }
            }
            "nt" => {
                // Next key threshold is required for inception and rotation events
                if matches!(ilk, Ilk::Icp | Ilk::Rot | Ilk::Dip | Ilk::Drt) && !has_field(sad, "nt")
                {
                    return Err(KERIError::ValidationError(
                        "Missing next key threshold field 'nt'".to_string(),
                    ));
                }

                // Validate as threshold string or parse as integer
                if let Some(SadValue::String(nt)) = sad.get("nt") {
                    if nt.parse::<u64>().is_err() {
                        return Err(KERIError::ValidationError(format!(
                            "Invalid next key threshold '{}': must be a non-negative integer",
                            nt
                        )));
                    }
                } else if has_field(sad, "nt") {
                    return Err(KERIError::ValidationError(
                        "Next key threshold 'nt' must be a string value".to_string(),
                    ));
                }
            }
            "n" => {
                // Next keys are required for inception and rotation events
                if matches!(ilk, Ilk::Icp | Ilk::Rot | Ilk::Dip | Ilk::Drt) {
                    // Must be an array of strings
                    if !has_string_array(sad, "n") {
                        return Err(KERIError::ValidationError(
                            "Missing or invalid next keys field 'n': must be an array of strings"
                                .to_string(),
                        ));
                    }

                    // Validate each key is a non-empty string
                    if let Some(SadValue::Array(keys)) = sad.get("n") {
                        for (i, key) in keys.iter().enumerate() {
                            if let Some(key_str) = key.as_str() {
                                if key_str.is_empty() {
                                    return Err(KERIError::ValidationError(format!(
                                        "Empty next key at index {} in 'n'",
                                        i
                                    )));
                                }
                            } else {
                                return Err(KERIError::ValidationError(format!(
                                    "Non-string next key at index {} in 'n'",
                                    i
                                )));
                            }
                        }
                    }
                }
            }
            "bt" => {
                // Backer threshold is required for inception and rotation events with backers
                if matches!(ilk, Ilk::Icp | Ilk::Rot | Ilk::Dip | Ilk::Drt)
                    && has_field(sad, "b")
                    && !has_field(sad, "bt")
                {
                    return Err(KERIError::ValidationError(
                        "Missing backer threshold field 'bt' when backers 'b' are present"
                            .to_string(),
                    ));
                }

                // Validate as threshold string or parse as integer if present
                if let Some(SadValue::String(bt)) = sad.get("bt") {
                    if bt.parse::<u64>().is_err() {
                        return Err(KERIError::ValidationError(format!(
                            "Invalid backer threshold '{}': must be a non-negative integer",
                            bt
                        )));
                    }
                } else if has_field(sad, "bt") {
                    return Err(KERIError::ValidationError(
                        "Backer threshold 'bt' must be a string value".to_string(),
                    ));
                }
            }
            "b" => {
                // Backers field must be an array of strings if present
                if has_field(sad, "b") && !has_string_array(sad, "b") {
                    return Err(KERIError::ValidationError(
                        "Invalid backers field 'b': must be an array of strings".to_string(),
                    ));
                }

                // Validate each backer is a non-empty string
                if let Some(SadValue::Array(backers)) = sad.get("b") {
                    for (i, backer) in backers.iter().enumerate() {
                        if let Some(backer_str) = backer.as_str() {
                            if backer_str.is_empty() {
                                return Err(KERIError::ValidationError(format!(
                                    "Empty backer at index {} in 'b'",
                                    i
                                )));
                            }
                        } else {
                            return Err(KERIError::ValidationError(format!(
                                "Non-string backer at index {} in 'b'",
                                i
                            )));
                        }
                    }
                }
            }
            "br" => {
                // Backer remove field must be an array of strings if present
                if has_field(sad, "br") && !has_string_array(sad, "br") {
                    return Err(KERIError::ValidationError(
                        "Invalid backer removes field 'br': must be an array of strings"
                            .to_string(),
                    ));
                }

                // Validate each backer is a non-empty string
                if let Some(SadValue::Array(backers)) = sad.get("br") {
                    for (i, backer) in backers.iter().enumerate() {
                        if let Some(backer_str) = backer.as_str() {
                            if backer_str.is_empty() {
                                return Err(KERIError::ValidationError(format!(
                                    "Empty backer remove at index {} in 'br'",
                                    i
                                )));
                            }
                        } else {
                            return Err(KERIError::ValidationError(format!(
                                "Non-string backer remove at index {} in 'br'",
                                i
                            )));
                        }
                    }
                }
            }
            "ba" => {
                // Backer add field must be an array if present
                if has_field(sad, "ba") && !is_array(sad, "ba") {
                    return Err(KERIError::ValidationError(
                        "Invalid backer adds field 'ba': must be an array".to_string(),
                    ));
                }
            }
            "c" => {
                // Configuration traits must be array or object if present
                if has_field(sad, "c") && !is_array(sad, "c") && !is_object(sad, "c") {
                    return Err(KERIError::ValidationError(
                        "Invalid config field 'c': must be an array or object".to_string(),
                    ));
                }
            }
            "a" => {
                // Anchors must be array or object if present
                if has_field(sad, "a") && !is_array(sad, "a") && !is_object(sad, "a") {
                    return Err(KERIError::ValidationError(
                        "Invalid anchors field 'a': must be an array or object".to_string(),
                    ));
                }
            }
            "di" => {
                // Delegator identifier is required for delegated events
                if matches!(ilk, Ilk::Dip | Ilk::Drt) && !has_non_empty_string(sad, "di") {
                    return Err(KERIError::ValidationError(
                        "Missing or empty delegator field 'di'".to_string(),
                    ));
                }
            }
            "dt" => {
                // Date-time is required for certain events
                if matches!(ilk, Ilk::Rpy | Ilk::Qry | Ilk::Exn) && !has_non_empty_string(sad, "dt")
                {
                    return Err(KERIError::ValidationError(
                        "Missing or empty date-time field 'dt'".to_string(),
                    ));
                }
            }
            "r" => {
                // Route is required for query and reply events
                if matches!(ilk, Ilk::Qry | Ilk::Rpy) && !has_non_empty_string(sad, "r") {
                    return Err(KERIError::ValidationError(
                        "Missing or empty route field 'r'".to_string(),
                    ));
                }
            }
            "q" => {
                // Query or payload must be object if present
                if has_field(sad, "q") && !is_object(sad, "q") {
                    return Err(KERIError::ValidationError(
                        "Invalid query field 'q': must be an object".to_string(),
                    ));
                }
            }
            "ri" => {
                // Registry identifier required for issuance and revocation events
                if matches!(ilk, Ilk::Iss | Ilk::Rev) && !has_non_empty_string(sad, "ri") {
                    return Err(KERIError::ValidationError(
                        "Missing or empty registry identifier 'ri'".to_string(),
                    ));
                }
            }
            "ii" => {
                // Issuer identifier required for certain events
                if matches!(ilk, Ilk::Bis | Ilk::Vcp) && !has_non_empty_string(sad, "ii") {
                    return Err(KERIError::ValidationError(
                        "Missing or empty issuer identifier field 'ii'".to_string(),
                    ));
                }
            }
            "rules" => {
                // Rules must be object if present
                if has_field(sad, "rules") && !is_object(sad, "rules") {
                    return Err(KERIError::ValidationError(
                        "Invalid rules field 'rules': must be an object".to_string(),
                    ));
                }
            }
            "e" => {
                // Exchange info must be object if present
                if has_field(sad, "e") && !is_object(sad, "e") {
                    return Err(KERIError::ValidationError(
                        "Invalid exchange field 'e': must be an object".to_string(),
                    ));
                }
            }
            // Add more fields here as needed
            _ => {
                // Other fields are not validated
            }
        }
    }

    // Add any cross-field validation rules here
    if let Some(SadValue::Array(keys)) = sad.get("k") {
        // If kt is present, ensure the threshold is not greater than the number of keys
        if let Some(SadValue::String(kt)) = sad.get("kt") {
            if let Ok(kt_val) = kt.parse::<usize>() {
                if kt_val > keys.len() && kt_val != 0 {
                    return Err(KERIError::ValidationError(format!(
                        "Invalid key threshold '{}': greater than number of keys {}",
                        kt,
                        keys.len()
                    )));
                }
            }
        }
    }

    if let Some(SadValue::Array(nkeys)) = sad.get("n") {
        // If nt is present, ensure the threshold is not greater than the number of next keys
        if let Some(SadValue::String(nt)) = sad.get("nt") {
            if let Ok(nt_val) = nt.parse::<usize>() {
                if nt_val > nkeys.len() && nt_val != 0 {
                    return Err(KERIError::ValidationError(format!(
                        "Invalid next key threshold '{}': greater than number of next keys {}",
                        nt,
                        nkeys.len()
                    )));
                }
            }
        }
    }

    // All validations passed
    Ok(())
}

/// Checks if a field exists in the Sadd map
fn has_field(sad: &Sadder, field: &str) -> bool {
    sad.contains_key(field)
}

/// Checks if a field exists and is a non-empty string
fn has_non_empty_string(sad: &Sadder, field: &str) -> bool {
    if let Some(SadValue::String(s)) = sad.get(field) {
        !s.is_empty()
    } else {
        false
    }
}

/// Checks if a field exists and is an array of strings
fn has_string_array(sad: &Sadder, field: &str) -> bool {
    if let Some(SadValue::Array(arr)) = sad.get(field) {
        arr.iter().all(|v| v.as_str().is_some())
    } else {
        false
    }
}

/// Checks if a field exists and is an array
fn is_array(sad: &Sadder, field: &str) -> bool {
    if let Some(value) = sad.get(field) {
        value.is_array()
    } else {
        false
    }
}

/// Checks if a field exists and is an object
fn is_object(sad: &Sadder, field: &str) -> bool {
    if let Some(value) = sad.get(field) {
        value.is_object()
    } else {
        false
    }
}

/// Creates a simpler version of the validate method that returns a string error
/// instead of a KERIError
pub fn is_valid(sad: &Sadder) -> Result<(), String> {
    match validate(sad) {
        Ok(()) => Ok(()),
        Err(e) => Err(e.to_string()),
    }
}

/// Creates a specific event type from this general structure
pub fn ilk(sad: &Sadder) -> Result<Ilk, KERIError> {
    let t = match sad.get("t") {
        Some(SadValue::String(t)) => t,
        _ => {
            return Err(KERIError::ValidationError(
                "Missing or invalid 't' field".to_string(),
            ))
        }
    };
    match t.as_str() {
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

pub fn get_primary_said_label(sad: &Sadder) -> Option<Said> {
    match ilk(sad) {
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
