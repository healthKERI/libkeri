use crate::cesr::diger::Diger;
use crate::cesr::{dig_dex, get_sizes, BaseMatter, Parsable};
use crate::errors::MatterError;
use crate::keri::core::serdering::{SadValue, Sadder};
use crate::keri::core::sizeify;
use crate::keri::{deversify, KERIError, Kinds};
use crate::Matter;
use std::any::Any;

///  Saider is Matter subclass for self-addressing identifier prefix using
///  derivation as determined by code from ked
#[derive(Debug, Clone)]
pub struct Saider {
    base: BaseMatter,
}

impl Matter for Saider {
    fn code(&self) -> &str {
        self.base.code()
    }
    fn raw(&self) -> &[u8] {
        self.base.raw()
    }
    fn qb64(&self) -> String {
        self.base.qb64()
    }
    fn qb64b(&self) -> Vec<u8> {
        self.base.qb64b()
    }
    fn qb2(&self) -> Vec<u8> {
        self.base.qb2()
    }
    fn soft(&self) -> &str {
        self.base.soft()
    }
    fn full_size(&self) -> usize {
        self.base.full_size()
    }
    fn size(&self) -> usize {
        self.base.size()
    }
    fn is_transferable(&self) -> bool {
        self.base.is_transferable()
    }
    fn is_digestive(&self) -> bool {
        self.base.is_digestive()
    }
    fn is_prefixive(&self) -> bool {
        self.base.is_prefixive()
    }
    fn is_special(&self) -> bool {
        self.base.is_special()
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl Parsable for Saider {
    fn from_qb64b(data: &mut Vec<u8>, strip: Option<bool>) -> Result<Self, MatterError> {
        let base = BaseMatter::from_qb64b(data, strip)?;
        if !dig_dex::TUPLE.contains(&(base.code())) {
            return Err(MatterError::UnsupportedCodeError(String::from(base.code())));
        }

        Ok(Saider { base })
    }

    fn from_qb2(data: &mut Vec<u8>, strip: Option<bool>) -> Result<Self, MatterError> {
        let base = BaseMatter::from_qb2(data, strip)?;
        if !dig_dex::TUPLE.contains(&(base.code())) {
            return Err(MatterError::UnsupportedCodeError(String::from(base.code())));
        }

        Ok(Saider { base })
    }
}

impl Saider {
    /// The placeholder character used to fill digest fields before calculation
    pub const DUMMY: char = '#';

    pub fn from_qb64(qb64: &str) -> Result<Self, MatterError> {
        let base = BaseMatter::from_qb64(qb64)?;
        if !dig_dex::TUPLE.contains(&(base.code())) {
            return Err(MatterError::UnsupportedCodeError(String::from(base.code())));
        }

        Ok(Saider { base })
    }

    /// Creates a new Saider from raw digest bytes
    ///
    /// # Parameters
    /// * `raw`: Raw digest bytes
    /// * `code`: Optional digest code
    ///
    /// # Returns
    /// * Result containing a new Saider instance or an error
    fn from_raw(raw: &[u8], code: Option<&str>) -> Result<Self, MatterError> {
        let code_str = code.unwrap_or(dig_dex::BLAKE3_256);
        let base = BaseMatter::new(Some(raw), Some(code_str), None, None)?;
        if !dig_dex::TUPLE.contains(&(base.code())) {
            return Err(MatterError::UnsupportedCodeError(String::from(base.code())));
        }

        Ok(Saider { base })
    }

    /// Creates a Saider instance from a SAD (Self-Addressable Data)
    ///
    /// # Parameters
    /// * `sad`: Self-addressable data dictionary
    /// * `code_opt`: Optional digest type code
    /// * `kind_opt`: Optional serialization kind
    /// * `label`: Field label containing the SAID
    /// * `ignore_opt`: Optional list of fields to ignore when generating SAID
    ///
    /// # Returns
    /// * Result containing a Saider or KERIError
    ///
    /// # Errors
    /// * Returns KERIError if sad is None or doesn't contain label field
    /// * Returns KERIError if code is unsupported
    pub fn from_sad(
        sad: &Sadder,
        label: &str,
        code_opt: Option<&str>,
        kind_opt: Option<&Kinds>,
        ignore_opt: Option<&[&str]>,
    ) -> Result<Self, KERIError> {
        // Check if sad exists and contains label field
        if sad.is_empty() || !sad.contains_key(label) {
            return Err(KERIError::ValueError(format!(
                "Missing label field={} in sad.",
                label
            )));
        }

        // Determine the code to use
        let code = if let Some(c) = code_opt {
            c.to_string()
        } else {
            // No code provided, try to get from SAID in sad
            if let Some(sad_value) = sad.get(label) {
                if let Some(sad_str) = sad_value.as_str() {
                    if !sad_str.is_empty() {
                        // Get code from said in sad
                        // Create a BaseMatter to extract the code
                        match BaseMatter::from_qb64(sad_str) {
                            Ok(matter) => matter.code().to_string(),
                            Err(_) => "E".to_string(), // Default to Blake3_256
                        }
                    } else {
                        // Use default code
                        "E".to_string() // Default to Blake3_256
                    }
                } else {
                    // Use default code
                    "E".to_string() // Default to Blake3_256
                }
            } else {
                // Use default code
                "E".to_string() // Default to Blake3_256
            }
        };

        // Check if code is supported
        if !dig_dex::TUPLE.contains(&code.as_str()) {
            return Err(KERIError::ValueError(format!(
                "Unsupported digest code = {}.",
                code
            )));
        }

        // Make copy of sad to derive said raw bytes and new sad
        // The _derive function sets the label field to dummy characters
        let (raw, _) = Self::_derive(sad, &code, kind_opt, label, ignore_opt)?;

        // Create a new Saider instance with the raw bytes and code
        Ok(Self::from_raw(&raw, Some(&code))?)
    }

    /// Serialize sad with serialization kind if provided else use
    /// embedded 'v' version string if provided else use default Kinds::Json
    ///
    /// # Parameters
    /// * `sad`: Sadder struct to serialize
    /// * `kind_opt`: Optional serialization algorithm, used to override the one in sad.v
    ///
    /// # Returns
    /// * Raw serialization of sad as bytes
    ///
    /// # Errors
    /// * Returns a KERIError if serialization fails
    pub fn _serialize(sad: Sadder, kind_opt: Option<&Kinds>) -> Result<Vec<u8>, KERIError> {
        // Default to JSON serialization
        let mut knd = Kinds::Json;

        // Extract kind from the version string if it exists
        if sad.contains_key("v") {
            match deversify(&sad["v"].as_str().unwrap_or("")) {
                Ok(smellage) => knd = Kinds::from(&smellage.kind)?,
                Err(e) => return Err(e),
            }
        }

        // Use provided kind if any, otherwise use the one extracted from version
        let kind = kind_opt.unwrap_or(&knd);

        // Serialize using the determined kind
        SadValue::dumps(&sad, kind)
    }

    /// Derives a self-addressing identifier from a Sadder struct
    ///
    /// # Returns
    /// * Tuple containing raw digest and updated Sadder with dummy characters
    ///
    /// # Parameters
    /// * `sad`: Sadder struct containing self-addressed data
    /// * `code`: Optional digest type code from dig_dex, defaults to self.code() if None
    /// * `kind_opt`: Optional serialization format (passed to _derive)
    /// * `label`: Optional field label to inject dummy characters into (passed to _derive)
    /// * `ignore`: Optional list of fields to ignore when generating SAID (passed to _derive)
    ///
    /// # Errors
    /// * Returns KERIError if derivation fails
    pub fn derive(
        &self,
        sad: &Sadder,
        code: Option<&str>,
        kind_opt: Option<&Kinds>,
        label: Option<&str>,
        ignore: Option<&[&str]>,
    ) -> Result<(Vec<u8>, Sadder), KERIError> {
        // Use self.code() if code parameter is None
        let code_to_use = code.unwrap_or_else(|| self.code());

        // Call _derive with the appropriate parameters
        Self::_derive(sad, code_to_use, kind_opt, label.unwrap_or("d"), ignore)
    }

    /// Derives raw said (self-addressing identifier) from a Sadder with dummy
    /// characters filled in the specified label field
    ///
    /// # Parameters
    /// * `sad`: Sadder to be injected with dummy and serialized
    /// * `code`: Digest type code from dig_dex
    /// * `kind_opt`: Optional serialization format (Json, Cbor, MsgPack)
    /// * `label`: Sadder field label to inject dummy characters into
    /// * `ignore`: Optional list of fields to ignore when generating SAID
    ///
    /// # Returns
    /// * Tuple containing raw digest and updated Sadder with dummy characters
    ///
    /// # Errors
    /// * Returns MatterError if code is unsupported
    /// * Returns KERIError if serialization fails
    pub fn _derive(
        sad: &Sadder,
        code: &str,
        kind_opt: Option<&Kinds>,
        label: &str,
        ignore: Option<&[&str]>,
    ) -> Result<(Vec<u8>, Sadder), KERIError> {
        // Validate the digest code
        if !dig_dex::TUPLE.contains(&code) {
            return Err(KERIError::ValueError(format!(
                "Unsupported digest code={}.",
                code
            )));
        }

        // Create a copy of sad so we don't modify the original
        let mut sad_copy = sad.clone();

        // Fill the specified label field with dummy characters to get size correct
        let sizes = get_sizes();
        let fs = sizes
            .get(code)
            .ok_or_else(|| KERIError::ValueError(format!("Unknown code size for {}", code)))?
            .fs
            .unwrap();

        // Fill in the dummy characters in the appropriate field
        sad_copy.insert(
            label.to_string(),
            SadValue::String(Self::DUMMY.to_string().repeat(fs as usize)),
        );

        // If versioned, update size in version string
        if sad_copy.contains_key("v") {
            let (_, _, _, processed_sad, _) = sizeify(&sad_copy, kind_opt, None)?;
            sad_copy = processed_sad;
        }

        // Create a copy for serialization, removing ignored fields
        let mut ser_copy = sad_copy.clone();

        // Remove ignored fields if any
        if let Some(ignored_fields) = ignore {
            for &field in ignored_fields {
                ser_copy.shift_remove(field);
            }
        }

        // Serialize the prepared Sadder
        let serialized = Self::_serialize(ser_copy, kind_opt)?;

        // Generate digest
        let digest = Diger::from_ser(&serialized, Some(code))?;

        Ok((digest.raw().to_vec(), sad_copy))
    }

    /// Verifies that the derivation from the provided sad matches the Saider's value
    ///
    /// # Returns
    /// * bool: True if the derivation from sad with dummy label field value replacement matches
    ///        the Saider's qb64b. If prefixed is true, also checks if the label field in sad matches
    ///        the Saider's qb64. If versioned is true and sad includes a version field 'v', also
    ///        validates that the version field matches the version field of the modified sad.
    ///
    /// # Parameters
    /// * `sad`: Sadder containing self-addressed data to verify against
    /// * `prefixed`: Whether to verify the label field in sad matches Saider's qb64
    /// * `versioned`: Whether to verify the version field in sad matches the derived sad's version
    /// * `kind_opt`: Optional serialization algorithm override
    /// * `label`: Field label for the SAID in the Sadder, defaults to "d"
    /// * `ignore`: Optional list of fields to ignore when generating SAID
    ///
    pub fn verify(
        &self,
        sad: &Sadder,
        prefixed: bool,
        versioned: bool,
        kind_opt: Option<&Kinds>,
        label: &str,
        ignore: Option<&[&str]>,
    ) -> bool {
        // Use a match expression to handle the Result
        self.verify_internal(sad, prefixed, versioned, kind_opt, label, ignore)
            .unwrap_or_else(|_| false)
    }

    // Internal method that returns a Result to simplify error handling
    fn verify_internal(
        &self,
        sad: &Sadder,
        prefixed: bool,
        versioned: bool,
        kind_opt: Option<&Kinds>,
        label: &str,
        ignore: Option<&[&str]>,
    ) -> Result<bool, KERIError> {
        // Try to derive SAID from the sad using this Saider's code
        let (raw, dsad) = Self::_derive(sad, self.code(), kind_opt, label, ignore)?;

        // Create a new Saider from the raw digest to compare with self
        let derived_saider = Saider::from_raw(&raw, Some(self.code()))?;

        // Check if the derived Saider's qb64b matches this Saider's qb64b
        if self.qb64b() != derived_saider.qb64b() {
            return Ok(false); // Not a match
        }

        // If versioned is true and sad has a non-empty version field,
        // verify that the version fields match
        if versioned && sad.contains_key("v") && sad["v"] != dsad["v"] {
            return Ok(false); // Version fields don't match
        }

        // If prefixed is true, verify that the label field in sad matches this Saider's qb64
        if prefixed {
            // Check which field to compare based on the label
            if sad[label].as_str().unwrap() != self.qb64() {
                return Ok(false);
            }
        }

        // All checks passed
        Ok(true)
    }

    /// Derives said from sad and injects it into a copy of sad
    ///
    /// # Returns
    /// * Tuple of (saider, sad) where saider is a Saider instance generated from sad
    ///   and sad is a copy of the parameter sad but with its label id field filled
    ///   with the generated said from saider
    ///
    /// # Parameters
    /// * `sad`: Serializable dictionary (Sadd)
    /// * `code`: Digest type code from `MtrDex`
    /// * `kind_opt`: Optional serialization algorithm of sad
    /// * `label`: Field label in which to inject said
    /// * `ignore_opt`: Optional fields to ignore when generating SAID
    ///
    /// # Errors
    /// * Returns KERIError if the label field is missing
    /// * Returns KERIError if the derive operation fails
    pub fn saidify(
        sad: Sadder,
        code: Option<String>,
        kind_opt: Option<&Kinds>,
        label: Option<String>,
        ignore_opt: Option<Vec<String>>,
    ) -> Result<(Self, Sadder), KERIError> {
        // Set default values if not provided
        let code = code.unwrap_or_else(|| "E".to_string()); // Assuming MtrDex.Blake3_256 is "E"
        let label = label.unwrap_or_else(|| "d".to_string()); // Assuming Saids.d is "d"

        // Convert ignore_opt from Vec<String> to &[&str] for _derive
        let ignore_refs: Option<Vec<&str>> = ignore_opt
            .as_ref()
            .map(|v| v.iter().map(|s| s.as_str()).collect());
        let ignore_slice: Option<&[&str]> = ignore_refs.as_ref().map(|v| v.as_slice());

        // Check if label exists in sad
        if !sad.contains_key(&label) {
            return Err(KERIError::ValueError(format!(
                "Missing id field labeled={} in sad.",
                label
            )));
        }

        // Derive the raw said and get the sad with dummy characters
        let (raw, sad_with_dummy) = Self::_derive(&sad, &code, kind_opt, &label, ignore_slice)?;
        let saider = Self::from_raw(&raw, Some(&code))?;

        // Create a copy of sad_with_dummy and inject the qb64 said
        let mut result_sad = sad_with_dummy;
        result_sad.insert(label, SadValue::String(saider.qb64()));

        Ok((saider, result_sad))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cesr::mtr_dex;
    use crate::keri::Kinds;
    use indexmap::{indexmap, IndexMap};

    #[test]
    fn test_saider() -> Result<(), KERIError> {
        // Test Saider object

        let code = mtr_dex::BLAKE3_256;
        let kind = &Kinds::Json;
        let label = "$id"; // Equivalent to Saids.dollar in Python

        // Test with valid said qb64
        let said0 = "EBG9LuUbFzV4OV5cGS9IeQWzy9SuyVFyVrpRc4l1xzPA";
        let saider = Saider::from_qb64b(&mut said0.as_bytes().to_vec(), None)?;
        assert_eq!(saider.code(), code);
        assert_eq!(saider.code(), mtr_dex::BLAKE3_256);
        assert_eq!(saider.qb64(), said0);

        // Create the equivalent of the Python JSON string
        let ser0 = br#"{"$id": "", "$schema": "http://json-schema.org/draft-07/schema#", "type": "object", "properties": {"a": {"type": "string"}, "b": {"type": "number"}, "c": {"type": "string", "format": "date-time"}}}"#;

        // Parse JSON to create the sad0 equivalent
        let sad0: Sadder = match serde_json::from_slice(ser0) {
            Ok(value) => value,
            Err(e) => {
                panic!("Failed to parse JSON: {}", e);
            }
        };

        // Call saidify function (equivalent to Python's Saider.saidify)
        let (saider, sad) =
            match Saider::saidify(sad0.clone(), None, None, Some(label.to_string()), None) {
                Ok(result) => result,
                Err(e) => {
                    panic!("Failed to saidify: {}", e);
                }
            };

        // Optional: store the expected SAID value for later use
        let said0 = "EMRvS7lGxc1eDleXBkvSHkFs8vUrslRcla6UXOJdcczw";
        assert_eq!(saider.qb64(), said0);

        // // Create a JSON Schema Sadder
        let mut sad0: IndexMap<String, SadValue> = indexmap!(
            "$id".to_string() => SadValue::String("".to_string()),
            "$schema".to_string() => SadValue::String("http://json-schema.org/draft-07/schema#".to_string()),
        );
        // Add type field
        sad0.insert("type".to_string(), SadValue::String("object".to_string()));

        // Create properties object
        let mut properties = IndexMap::new();

        // Add "a" property
        let mut a_prop = IndexMap::new();
        a_prop.insert("type".to_string(), SadValue::String("string".to_string()));
        properties.insert("a".to_string(), SadValue::Object(a_prop));

        // Add "b" property
        let mut b_prop = IndexMap::new();
        b_prop.insert("type".to_string(), SadValue::String("number".to_string()));
        properties.insert("b".to_string(), SadValue::Object(b_prop));

        // Add "c" property
        let mut c_prop = IndexMap::new();
        c_prop.insert("type".to_string(), SadValue::String("string".to_string()));
        c_prop.insert(
            "format".to_string(),
            SadValue::String("date-time".to_string()),
        );
        properties.insert("c".to_string(), SadValue::Object(c_prop));

        // Add properties to schema
        sad0.insert("properties".to_string(), SadValue::Object(properties));

        // Derive SAID from sad0
        let (raw, dsad) = Saider::_derive(&sad0, code, Some(kind), label, None)?;
        let json_str = serde_json::to_string_pretty(&dsad)
            .unwrap_or_else(|_| "Error serializing to JSON".to_string());

        let saider = Saider::from_raw(&raw, Some(code))?;

        assert_eq!(
            saider.qb64(),
            "EMRvS7lGxc1eDleXBkvSHkFs8vUrslRcla6UXOJdcczw"
        );
        let said0 = "EMRvS7lGxc1eDleXBkvSHkFs8vUrslRcla6UXOJdcczw";

        // Create Sadder with valid said in $id field
        let mut sad_with_id = sad0.clone();
        sad_with_id.insert("$id".to_string(), SadValue::String(said0.to_string()));

        // Test verification with prefixed=true
        assert!(saider.verify(&sad_with_id, true, true, Some(kind), label, None));

        // Test verification with prefixed=false on the empty $id Sadder
        let sad1 = sad0.clone();
        sad_with_id.insert("$id".to_string(), SadValue::String("".to_string()));

        assert!(saider.verify(&sad1, false, true, Some(kind), label, None));
        assert!(!saider.verify(&sad1, true, true, Some(kind), label, None));

        // Initialize saider from Sadder (similar to Python `Saider(sad=sad1, code=code, label=label)`)
        let (raw, _) = Saider::_derive(&sad1, code, Some(kind), label, None)?;
        let saider = Saider::from_raw(&raw, Some(code))?;

        assert_eq!(saider.code(), code);
        assert_eq!(saider.code(), mtr_dex::BLAKE3_256);
        assert_eq!(saider.qb64(), said0);

        assert!(saider.verify(&sad1, false, true, Some(kind), label, None));
        assert!(!saider.verify(&sad1, true, true, Some(kind), label, None));

        // Constants for testing
        let label = "$id";
        let code = mtr_dex::BLAKE2B_256;

        // Test initializing with qb64
        let said2 = "FG1_1lgNJ69QPnJK-pD5s8cinFFYhnGN8nuyz8Mdrezg";
        let saider = Saider::from_qb64(said2)?;
        assert_eq!(saider.code(), code);
        assert_eq!(saider.code(), mtr_dex::BLAKE2B_256);
        assert_eq!(saider.qb64(), said2);

        // Test creating from JSON data with different SAID
        let ser2 = br#"{"$id":"FW1_1lgNJ69QPnJK-pD5s8cinFFYhnGN8nuyz8Mdrezg","$schema":"http://json-schema.org/draft-07/schema#","type":"object","properties":{"a":{"type":"string"},"b":{"type":"number"},"c":{"type":"string","format":"date-time"}}}"#;
        let sad2: Sadder = serde_json::from_slice(ser2).unwrap();

        // Test saidify with specified code and label
        let (saider, sad) = Saider::saidify(
            sad2.clone(),
            Some(mtr_dex::BLAKE2B_256.to_string()),
            Some(&Kinds::Json),
            Some("$id".to_string()),
            None,
        )?;
        assert_eq!(
            saider.qb64(),
            "FFtf9ZYDSevUD5ySvqQ-bPHIpxRWIZxjfJ7ss_DHa3s4"
        );
        let said2 = "FFtf9ZYDSevUD5ySvqQ-bPHIpxRWIZxjfJ7ss_DHa3s4";

        // Test verifying with new SAD that includes the correct SAID
        let ser2 = br#"{"$id":"FFtf9ZYDSevUD5ySvqQ-bPHIpxRWIZxjfJ7ss_DHa3s4","$schema":"http://json-schema.org/draft-07/schema#","type":"object","properties":{"a":{"type":"string"},"b":{"type":"number"},"c":{"type":"string","format":"date-time"}}}"#;
        let sad2: Sadder = serde_json::from_slice(ser2).unwrap();

        assert!(saider.verify(&sad2, true, false, None, label, None));

        // Test sad1 for comparison operations
        let ser0 = br#"{"$id":"","$schema":"http://json-schema.org/draft-07/schema#","type":"object","properties":{"a":{"type":"string"},"b":{"type":"number"},"c":{"type":"string","format":"date-time"}}}"#;
        let sad1: Sadder = serde_json::from_slice(ser0).unwrap();

        // Initialize from sad with explicit code
        let saider = Saider::from_sad(&sad1, label, Some(mtr_dex::BLAKE2B_256), None, None)?;
        assert_eq!(saider.code(), mtr_dex::BLAKE2B_256);
        assert_eq!(saider.qb64(), said2);
        assert!(saider.verify(&sad1, false, false, None, label, None));
        assert!(!saider.verify(&sad1, true, false, None, label, None));
        assert!(saider.verify(&sad2, true, false, None, label, None));

        // Initialize from sad2 without explicit code (should get code from sad)
        let saider = Saider::from_sad(&sad2, label, None, None, None)?;
        assert_eq!(saider.code(), mtr_dex::BLAKE2B_256);
        assert_eq!(saider.qb64(), said2);
        assert!(saider.verify(&sad1, false, false, None, label, None));
        assert!(!saider.verify(&sad1, true, false, None, label, None));
        assert!(saider.verify(&sad2, true, false, None, label, None));

        // Test saidify with a copy of sad1
        let sad1_copy = sad1.clone();
        let (saider, sad) = Saider::saidify(
            sad1_copy,
            Some(mtr_dex::BLAKE2B_256.to_string()),
            None,
            Some(label.to_string()),
            None,
        )?;
        assert_eq!(saider.code(), mtr_dex::BLAKE2B_256);
        assert_eq!(saider.qb64(), said2);
        assert_ne!(sad, sad1);

        // Check sad1's label is empty while sad has the correct SAID
        if let Some(sad1_label) = sad1.get(label) {
            assert!(sad1_label.as_str().unwrap().is_empty());
        }
        if let Some(sad_label) = sad.get(label) {
            assert_eq!(sad_label.as_str().unwrap(), said2);
        }

        assert!(saider.verify(&sad, true, false, None, label, None));
        assert!(saider.verify(&sad1, false, false, None, label, None));
        assert!(!saider.verify(&sad1, true, false, None, label, None));
        assert!(saider.verify(&sad2, true, false, None, label, None));

        // Test with default id field label 'd' and a versioned SAD
        // let label = "d";
        // let code = mtr_dex::BLAKE3_256; // Default code
        //
        // // Create a versioned sad
        // let vs = versify("KERI", &Versionage { major: 1, minor: 0 }, "JSON", 0)?;
        // assert_eq!(vs, "KERI10JSON000000_");
        //
        // let mut sad4 = IndexMap::new();
        // sad4.insert("v".to_string(), SadValue::String(vs));
        // sad4.insert("t".to_string(), SadValue::String("rep".to_string()));
        // sad4.insert("d".to_string(), SadValue::String("".to_string())); // Empty SAID
        // sad4.insert("dt".to_string(), SadValue::String("2020-08-22T17:50:12.988921+00:00".to_string()));
        // sad4.insert("r".to_string(), SadValue::String("logs/processor".to_string()));
        //
        // // Create nested 'a' field
        // let mut a_field = IndexMap::new();
        // a_field.insert("d".to_string(), SadValue::String("EBabiu_JCkE0GbiglDXNB5C4NQq-hiGgxhHKXBxkiojg".to_string()));
        // a_field.insert("i".to_string(), SadValue::String("EB0_D51cTh_q6uOQ-byFiv5oNXZ-cxdqCqBAa4JmBLtb".to_string()));
        // a_field.insert("name".to_string(), SadValue::String("John Jones".to_string()));
        // a_field.insert("role".to_string(), SadValue::String("Founder".to_string()));
        //
        // sad4.insert("a".to_string(), SadValue::Object(a_field));
        //
        // // Create Saider from sad without version
        // let saider = Saider::from_sad(&sad4, None, None, label, None)?;
        // assert_eq!(saider.code(), code);
        // assert_eq!(saider.qb64(), "ELzewBpZHSENRP-sL_G_2Ji4YDdNkns9AzFzufleJqdw");
        // assert!(saider.verify(&sad4, Some(false), Some(false), None, label, None)?);
        // assert!(!saider.verify(&sad4, Some(false), None, None, label, None)?);
        // assert!(!saider.verify(&sad4, Some(true), Some(false), None, label, None)?);
        //
        // // Create a copy with the SAID injected
        // let mut sad5 = sad4.clone();
        // sad5.insert(label.to_string(), SadValue::String(saider.qb64()));
        // assert!(saider.verify(&sad5, Some(true), Some(false), None, label, None)?);
        //
        // // Create another copy with both SAID and version updated
        // let mut sad6 = sad5.clone();
        // let (_, updated_sad) = saider.derive(&sad4, None, None, Some(label), None)?;
        // if let Some(SadValue::String(v)) = updated_sad.get("v") {
        //     sad6.insert("v".to_string(), SadValue::String(v.clone()));
        // }
        // assert!(saider.verify(&sad6, Some(true), None, None, label, None)?);
        //
        // let said3 = saider.qb64();
        // let saider = Saider::from_qb64(said3)?;
        // assert_eq!(saider.code(), code);
        // assert_eq!(saider.qb64(), said3);
        //
        // // Test serialization and verification with coring functions
        // let ser5 = coring::dumps(&sad5, &Kinds::Json)?;
        //
        // // The exact byte comparison is tricky due to JSON serialization differences
        // // Instead, we'll verify deserialization works correctly
        // let sad3 = coring::loads(&ser5, None, Kinds::Json)?;
        // assert!(!saider.verify(&sad3, Some(true), None, None, label, None)?);
        // assert!(saider.verify(&sad3, Some(true), Some(false), None, label, None)?);
        //
        // // Test saidify on sad4
        // assert_eq!(sad4[label].as_str().unwrap(), "");
        // if let Some(SadValue::String(v)) = sad4.get("v") {
        //     assert_eq!(v, "KERI10JSON000000_");
        // }
        //
        // let (saider, sad) = Saider::saidify(
        //     sad4.clone(),
        //     None,
        //     None,
        //     Some(label.to_string()),
        //     None
        // )?;
        // assert_eq!(saider.code(), code);
        // assert_eq!(saider.qb64(), said3);
        // assert_ne!(sad, sad4);
        // assert_eq!(sad4[label].as_str().unwrap(), "");
        // assert_eq!(sad[label].as_str().unwrap(), said3);
        //
        // assert!(saider.verify(&sad, Some(true), None, None, label, None)?);
        // assert!(!saider.verify(&sad4, Some(true), None, None, label, None)?);
        // assert!(!saider.verify(&sad4, Some(false), None, None, label, None)?);
        // assert!(saider.verify(&sad4, Some(false), Some(false), None, label, None)?);
        // assert!(saider.verify(&sad3, Some(true), Some(false), None, label, None)?);
        //
        // // Test with non-default digest code
        // let saider = Saider::from_sad(&sad3, Some(mtr_dex::BLAKE2B_256), None, label, None)?;
        // assert_eq!(saider.code(), mtr_dex::BLAKE2B_256);
        // assert_ne!(saider.qb64(), said3);
        // assert!(saider.verify(&sad3, Some(false), Some(false), None, label, None)?);
        // assert!(!saider.verify(&sad3, Some(true), None, None, label, None)?);
        //
        // let (saider, sad7) = Saider::saidify(
        //     sad3.clone(),
        //     Some(mtr_dex::BLAKE2B_256.to_string()),
        //     None,
        //     Some(label.to_string()),
        //     None
        // )?;
        // assert_ne!(saider.qb64(), said3);
        // assert!(saider.verify(&sad7, Some(true), None, None, label, None)?);
        //
        // assert!(saider.verify(&sad4, Some(false), Some(false), None, label, None)?);
        // assert!(!saider.verify(&sad4, Some(true), None, None, label, None)?);
        //
        // let (saider, sad8) = Saider::saidify(
        //     sad4.clone(),
        //     Some(mtr_dex::BLAKE2B_256.to_string()),
        //     None,
        //     Some(label.to_string()),
        //     None
        // )?;
        // assert_ne!(saider.qb64(), said3);
        // assert!(saider.verify(&sad8, Some(true), None, None, label, None)?);
        //
        // // Test getting kind from version string
        // let vs = versify("KERI", &Versionage { major: 1, minor: 0 }, "MGPK", 0)?;
        // assert_eq!(vs, "KERI10MGPK000000_");
        //
        // let mut sad9 = sad4.clone();
        // sad9.insert("v".to_string(), SadValue::String(vs));
        //
        // let saider = Saider::from_sad(&sad9, None, None, label, None)?;
        // assert_eq!(saider.code(), code);
        // let said9 = saider.qb64();
        // assert_eq!(said9, "EJyT3AEkPq3clvvZ2IZN_cU0kcbcDiAnNRULl_tTWzJo");
        // assert_ne!(said9, said3);
        //
        // assert!(saider.verify(&sad9, Some(false), Some(false), None, label, None)?);
        // assert!(!saider.verify(&sad9, Some(true), None, None, label, None)?);
        // assert!(!saider.verify(&sad3, Some(false), None, None, label, None)?);
        // assert!(!saider.verify(&sad3, Some(true), None, None, label, None)?);
        //
        // let (saider, sad10) = Saider::saidify(
        //     sad9.clone(),
        //     None,
        //     None,
        //     Some(label.to_string()),
        //     None
        // )?;
        // assert_eq!(saider.qb64(), said9);
        // assert!(saider.verify(&sad10, Some(true), None, None, label, None)?);
        //
        // // Test ignoring fields from SAID calculation
        // let mut sad = IndexMap::new();
        // sad.insert("d".to_string(), SadValue::String("".to_string()));
        // sad.insert("first".to_string(), SadValue::String("John".to_string()));
        // sad.insert("last".to_string(), SadValue::String("Doe".to_string()));
        // sad.insert("read".to_string(), SadValue::Bool(false));
        //
        // let ignore = vec!["read"];
        // let ignore_slice: Vec<&str> = ignore.iter().map(|s| s.as_str()).collect();
        //
        // let saider1 = Saider::from_sad(&sad, None, None, "d", Some(&ignore_slice))?;
        // assert_eq!(saider1.qb64(), "EBam6rzvfq0yF6eI7Czrg3dUVhqg2cwNkSoJvyHWPj3p");
        //
        // let (saider2, sad2) = Saider::saidify(
        //     sad.clone(),
        //     None,
        //     None,
        //     Some("d".to_string()),
        //     Some(ignore.clone().into_iter().map(String::from).collect())
        // )?;
        // assert_eq!(saider2.qb64(), saider1.qb64());
        // assert_eq!(sad2["d"].as_str().unwrap(), saider2.qb64());
        // assert_eq!(sad2["d"].as_str().unwrap(), saider1.qb64());
        // assert_eq!(sad2["read"].as_bool().unwrap(), false);
        //
        // assert!(saider1.verify(&sad2, Some(true), None, None, "d", Some(&ignore_slice))?);
        //
        // // Change the 'read' field that is ignored and verify it still works
        // let mut sad2 = sad2.clone();
        // sad2.insert("read".to_string(), SadValue::Bool(true));
        // assert!(saider1.verify(&sad2, Some(true), None, None, "d", Some(&ignore_slice))?);
        //
        // let saider3 = Saider::from_sad(&sad2, None, None, "d", Some(&ignore_slice))?;
        // assert_eq!(saider3.qb64(), saider2.qb64());
        // assert_eq!(sad2["read"].as_bool().unwrap(), true);

        Ok(())
    }
}
