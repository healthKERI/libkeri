use serde::{de, ser};
use serde::{Deserializer, Serializer};
use serde_json::Number;
use std::fmt;
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use serde::ser::{SerializeMap, SerializeSeq};
use crate::keri::{KERIError, Kinds};

#[derive(Clone)]
pub enum SadValue {
    Bool(bool),
    Number(Number),
    String(String),
    Array(Vec<SadValue>),
    Object(IndexMap<String, SadValue>),
}

pub type Sadd = IndexMap<String, SadValue>;

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
    pub fn loads(raw: &[u8], size: Option<usize>, kind: Kinds) -> Result<Sadd, KERIError> {
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
                let sadder = rmp_serde::from_slice(data).map_err(|e| KERIError::MgpkError(e.to_string()))?;
                Ok(sadder)
            }

            Kinds::Cbor => {
                let sadder = serde_cbor::from_slice(data).map_err(|e| KERIError::CborError(e.to_string()))?;
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
    pub fn dumps(sad: &Sadd, kind: &Kinds) -> Result<Vec<u8>, KERIError> {
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
                _ => return None
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
                SadValue::Object(map) => {
                    map.get_mut(&token)?
                }
                SadValue::Array(vec) => {
                    if let Ok(index) = token.parse::<usize>() {
                        vec.get_mut(index)?
                    } else {
                        return None;
                    }
                }
                _ => return None
            };
        }

        match target {
            SadValue::Object(map) => {
                map.get_mut(&last_token)
            }
            SadValue::Array(vec) => {
                if let Ok(index) = last_token.parse::<usize>() {
                    vec.get_mut(index)
                } else {
                    None
                }
            }
            _ => None
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
