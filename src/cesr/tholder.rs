use crate::cesr::bexter::Bexter;
use crate::cesr::number::Number;
use crate::cesr::{bex_dex, num_dex, BaseMatter, Parsable};
use crate::errors::MatterError;
use crate::keri::core::serdering::SadValue;
use crate::Matter;
use num_rational::Rational32;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::fmt::Debug;

/// Represents a weight specification for weighted thresholds
#[derive(Debug, Clone, PartialEq)]
pub enum WeightSpec {
    /// Simple fractional weight
    Simple(Rational32),

    /// Weighted threshold with key weight and list of witness weights
    WeightedVec(Vec<WeightSpec>),

    /// Weighted threshold with key weight and list of witness weights
    WeightedMap(Rational32, Vec<Rational32>),
}

/// Tholder is KERI Signing Threshold Satisfaction struct
/// It evaluates satisfaction based on ordered list of indices of
/// verified signatures where indices correspond to offsets in key list.
#[derive(Debug, Clone)]
pub struct Tholder {
    /// True if fractional weighted threshold, False if numeric
    _weighted: bool,

    /// Minimum size of keys list
    _size: usize,

    /// Original signing threshold (for sith property)
    _sith: TholderSith,

    /// Parsed signing threshold for calculating satisfaction
    _thold: TholderThold,

    /// Bexter instance of weighted signing threshold or None
    _bexter: Option<Bexter>,

    /// Number instance of integer threshold or None
    _number: Option<Number>,
}

/// Represents the different forms of signing threshold (sith)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum TholderSith {
    /// Non-negative integer threshold (M of N)
    Integer(usize),

    /// Hex string representation of integer threshold
    HexString(String),

    /// Json representation of threshold
    Json(String),

    /// Single clause of fractional weights
    Weights(Vec<WeightedSithElement>),
}

impl TholderSith {
    pub fn from_sad_value(val: SadValue) -> Result<Self, MatterError> {
        match val {
            SadValue::Number(num) => Ok(TholderSith::Integer(num.as_u64().unwrap() as usize)),
            SadValue::String(s) => {
                if s.contains("[") {
                    Ok(TholderSith::Json(s))
                } else {
                    Ok(TholderSith::HexString(s))
                }
            }
            _ => Err(MatterError::ValueError(format!(
                "invalid sith value: {:?}",
                val
            ))),
        }
    }
}

impl fmt::Display for TholderSith {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            TholderSith::Integer(n) => write!(f, "{}", n),
            TholderSith::HexString(s) => write!(f, "{}", s),
            TholderSith::Json(s) => write!(f, "{}", s),
            TholderSith::Weights(w) => {
                // Format the weights as a JSON string
                match serde_json::to_string(w) {
                    Ok(json) => write!(f, "{}", json),
                    Err(_) => write!(f, "<invalid weights>"),
                }
            }
        }
    }
}

// Also implement for the WeightedSithElement for completeness
impl fmt::Display for WeightedSithElement {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match serde_json::to_string(self) {
            Ok(json) => write!(f, "{}", json),
            Err(_) => write!(f, "<invalid weight element>"),
        }
    }
}

/// Represents the different elements that can appear in a weight clause
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum WeightedSithElement {
    /// Simple fraction string like "1/2"
    Simple(String),

    /// Array of nested weights like ["1/2", "1/3", ["1/3", "1/3", "1/3"]]
    Array(Vec<WeightedSithElement>),

    /// Complex weight with key as fraction and value as list of fractions like {"1/2": ["1/2", "1/3"]}
    Complex(HashMap<String, Vec<WeightedSithElement>>),
}

/// Represents the parsed threshold for calculating satisfaction
#[derive(Debug, Clone, PartialEq)]
pub enum TholderThold {
    /// Simple integer threshold
    Integer(usize),

    /// Weighted threshold clauses
    Weighted(Vec<Vec<WeightSpec>>),
}

impl Default for Tholder {
    fn default() -> Self {
        Tholder {
            _weighted: false,
            _size: 0,
            _sith: TholderSith::HexString(String::new()),
            _thold: TholderThold::Integer(0),
            _bexter: None,
            _number: None,
        }
    }
}

impl Tholder {
    /// Creates a new Tholder with the provided threshold
    ///
    /// # Arguments
    ///
    /// * `thold` - Optional computed threshold representation
    /// * `limen` - Optional CESR serialized threshold
    /// * `sith` - Optional JSON/CBOR/MGPK serializable threshold
    ///
    /// # Returns
    ///
    /// A new Tholder instance or an error
    pub fn new(
        thold: Option<TholderThold>,
        limen: Option<Vec<u8>>,
        sith: Option<TholderSith>,
    ) -> Result<Self, MatterError> {
        if let Some(t) = thold {
            return Self::process_thold(t);
        } else if let Some(l) = limen {
            let mut tholder = Tholder::default();
            tholder.process_limen(l.as_slice(), Some(false))?;
            return Ok(tholder);
        } else if let Some(s) = sith {
            let mut tholder = Tholder::default();
            tholder.process_sith(s)?;
            return Ok(tholder);
        }

        Err(MatterError::EmptyMaterialError(
            "Missing threshold expression.".to_string(),
        ))
    }

    /// Process a computed threshold representation
    fn process_thold(thold: TholderThold) -> Result<Self, MatterError> {
        let mut tholder = Tholder::default();
        match thold {
            TholderThold::Integer(num) => {
                tholder.process_unweighted(num)?;
            }
            TholderThold::Weighted(clauses) => {
                tholder.process_weighted(clauses)?;
            }
        }

        Ok(tholder)
    }

    /// Process limen input
    ///
    /// # Arguments
    ///
    /// * `limen` - CESR encoded qb64 threshold (weighted or unweighted)
    /// * `strip` - Optional flag to strip trailing pad bytes
    pub fn process_limen(&mut self, limen: &[u8], strip: Option<bool>) -> Result<(), MatterError> {
        let matter = BaseMatter::from_qb64b(&mut limen.to_vec(), strip)?;

        if num_dex::MAP.contains_key(matter.code()) {
            let number = Number::new(Some(matter.raw()), Some(matter.code()), None, None)?;
            self.process_unweighted(number.num() as usize)?;
        } else if bex_dex::MAP.contains_key(matter.code()) {
            // Convert to fractional thold expression
            let bexter = Bexter::new(Some(matter.raw()), Some(matter.code()), None, None)?;
            let t = bexter.bext()?.replace('s', "/");

            // Get clauses
            let clauses: Vec<&str> = t.split('a').collect();

            let mut thold = Vec::new();
            for c in clauses {
                let c_parts: Vec<&str> = c.split('c').collect();
                let mut clause = Vec::new();

                for e in c_parts {
                    if let Some(k_pos) = e.find('k') {
                        let k = &e[..k_pos];
                        let v = &e[(k_pos + 1)..];

                        let v_parts: Vec<&str> = v.split('v').collect();
                        let weights: Vec<Rational32> = v_parts
                            .iter()
                            .map(|w| Self::weight(w))
                            .collect::<Result<Vec<Rational32>, _>>()?;

                        clause.push(WeightSpec::WeightedMap(Self::weight(k)?, weights));
                    } else {
                        clause.push(WeightSpec::Simple(Self::weight(e)?));
                    }
                }

                thold.push(clause);
            }

            self.process_weighted(thold)?;
        } else {
            return Err(MatterError::InvalidCode(format!(
                "Invalid code for limen = {}",
                matter.code()
            )));
        }

        Ok(())
    }

    /// Process attributes for fractionally weighted threshold sith
    ///
    /// # Arguments
    ///
    /// * `sith` - Signing threshold (current or next) expressed as one of the TholderSith variants:
    ///   - Integer: non-negative integer of threshold number (M-of-N threshold)
    ///   - HexString: non-negative hex string of threshold number (M-of-N threshold)
    ///   - SimpleWeights: a single clause of fractional weights
    ///   - ComplexWeights: multiple clauses of fractional weights (AND conditions)
    pub fn process_sith(&mut self, sith: TholderSith) -> Result<(), MatterError> {
        match sith {
            TholderSith::Integer(threshold) => self.process_unweighted(threshold),

            TholderSith::HexString(hex_str) => {
                // Parse the hex string to get the integer threshold
                match i32::from_str_radix(&hex_str, 16) {
                    Ok(threshold) => self.process_unweighted(threshold as usize),
                    Err(_) => Err(MatterError::ValueError(format!(
                        "Invalid hex string sith = {}",
                        hex_str
                    ))),
                }
            }

            TholderSith::Json(json_val) => {
                let clauses: Vec<WeightedSithElement> =
                    serde_json::from_str(json_val.as_str()).unwrap();
                if clauses.is_empty() {
                    return Err(MatterError::ValueError("Empty weight list".to_string()));
                }

                // Convert all clauses
                let mut thold = Vec::new();
                for clause in clauses {
                    let processed_clause = self.process_weight_clause(&clause)?;
                    thold.push(processed_clause);
                }
                self.process_weighted(thold)
            }

            TholderSith::Weights(clauses) => {
                if clauses.is_empty() {
                    return Err(MatterError::ValueError("Empty weight list".to_string()));
                }

                // Convert all clauses
                let mut thold = Vec::new();
                for clause in clauses {
                    let processed_clause = self.process_weight_clause(&clause)?;
                    thold.push(processed_clause);
                }
                self.process_weighted(thold)
            }
        }
    }

    /// Helper function to process a clause of weight elements
    fn process_weight_clause(
        &self,
        clause: &WeightedSithElement,
    ) -> Result<Vec<WeightSpec>, MatterError> {
        let mut processed_clause = Vec::new();

        match clause {
            WeightedSithElement::Simple(weight_str) => {
                let weight = Self::weight(weight_str)?;
                processed_clause.push(WeightSpec::Simple(weight));
            }

            WeightedSithElement::Array(sub_clauses) => {
                let mut processed_sub_clauses = Vec::new();
                for clause in sub_clauses {
                    let mut processed_clause = self.process_weight_clause(&clause)?;
                    processed_clause.append(&mut processed_sub_clauses);
                }

                processed_clause.push(WeightSpec::WeightedVec(processed_sub_clauses))
            }

            WeightedSithElement::Complex(weights) => {
                let key_weight = Self::weight("")?;

                let nested_weights: Result<Vec<Rational32>, _> =
                    weights.iter().map(|_w| Self::weight("")).collect();

                processed_clause.push(WeightSpec::WeightedMap(key_weight, nested_weights?));
            }
        }

        Ok(processed_clause)
    }

    /// Evaluates if the provided verified signature indices satisfy the threshold
    ///
    /// # Arguments
    ///
    /// * `indices` - List of indices of verified signatures
    ///
    /// # Returns
    ///
    /// True if the indices satisfy the threshold, false otherwise
    pub fn satisfy(&self, indices: &[usize]) -> bool {
        if self._weighted {
            self.satisfy_weighted(indices)
        } else {
            self.satisfy_numeric(indices)
        }
    }

    /// Evaluates if indices satisfy a numeric threshold
    fn satisfy_numeric(&self, indices: &[usize]) -> bool {
        if let TholderThold::Integer(num) = self._thold {
            indices.len() >= num
        } else {
            false
        }
    }

    /// Evaluates if indices satisfy a weighted threshold
    fn satisfy_weighted(&self, _indices: &[usize]) -> bool {
        // Placeholder implementation
        false
    }

    /// Returns whether the threshold is weighted or not
    pub fn weighted(&self) -> bool {
        self._weighted
    }

    /// Returns the parsed threshold
    pub fn thold(&self) -> &TholderThold {
        &self._thold
    }

    /// Returns the minimum size of keys list
    pub fn size(&self) -> usize {
        self._size
    }

    /// Returns the CESR serializable threshold
    pub fn limen(&self) -> Vec<u8> {
        if self._weighted {
            // Assuming Bexter has a qb64b method that returns Vec<u8>
            self._bexter.as_ref().unwrap().qb64b()
        } else {
            // Assuming Number has a qb64b method that returns Vec<u8>
            self._number.as_ref().unwrap().qb64b()
        }
    }

    /// Returns the JSON serializable threshold
    pub fn sith(&self) -> TholderSith {
        match &self._thold {
            TholderThold::Weighted(_clauses) => {
                // Convert weighted threshold back to sith format
                // This is a simplified placeholder
                TholderSith::Weights(vec![]) // Would need actual implementation
            }
            TholderThold::Integer(n) => {
                // Convert int to hex string
                TholderSith::HexString(format!("{:x}", n))
            }
        }
    }

    /// Returns JSON serialization of sith expression
    pub fn json(&self) -> String {
        serde_json::to_string(&self.sith()).unwrap_or_default()
    }

    /// Returns the numeric threshold value if not weighted
    pub fn num(&self) -> Option<usize> {
        if !self._weighted {
            if let TholderThold::Integer(n) = self._thold {
                return Some(n);
            }
        }
        None
    }

    // Process unweighted (numeric) threshold
    fn process_unweighted(&mut self, thold: usize) -> Result<(), MatterError> {
        if thold == 0 {
            // Special case for zero threshold (allowed for next threshold)
            self._weighted = false;
            self._size = thold;
            self._sith = TholderSith::Integer(thold);
            self._thold = TholderThold::Integer(thold);
            self._bexter = None;
            self._number = Some(Number::from_numh(format!("{:x}", thold).as_str())?);

            Ok(())
        } else {
            self._weighted = false;
            self._size = thold;
            self._sith = TholderSith::Integer(thold);
            self._thold = TholderThold::Integer(thold);
            self._bexter = None;
            self._number = Some(Number::from_numh(format!("{:x}", thold).as_str())?);

            Ok(())
        }
    }

    /// Process weighted threshold
    fn process_weighted(&mut self, thold: Vec<Vec<WeightSpec>>) -> Result<(), MatterError> {
        // Validate threshold clauses
        for clause in &thold {
            // Validate that sum of top-level weights in clause must be >= 1
            let mut top_weights = Vec::new();

            for e in clause {
                match e {
                    WeightSpec::Simple(weight) => {
                        top_weights.push(*weight);
                    }
                    WeightSpec::WeightedMap(key_weight, nested_weights) => {
                        top_weights.push(*key_weight);

                        // Validate that sum of nested weights must be >= 1
                        let sum_nested: Rational32 = nested_weights.iter().sum();
                        if sum_nested < Rational32::new(1, 1) {
                            return Err(MatterError::ValueError(format!(
                                "Invalid sith clause, nested clause weight sum must be >= 1. Got: {:?}",
                                sum_nested
                            )));
                        }
                    }
                    WeightSpec::WeightedVec(nested_specs) => {
                        // Handle nested vector case similar to Complex case
                        let mut nested_sum = Rational32::new(0, 1);

                        for nested_spec in nested_specs {
                            if let WeightSpec::Simple(weight) = nested_spec {
                                nested_sum = nested_sum + *weight;
                            }
                            // Could handle deeper nesting here if needed
                        }

                        if nested_sum < Rational32::new(1, 1) {
                            return Err(MatterError::ValueError(format!(
                                "Invalid sith clause, nested vec weight sum must be >= 1. Got: {:?}",
                                nested_sum
                            )));
                        }

                        // Add a weight for this nested vector (could be a parameter)
                        top_weights.push(Rational32::new(1, 1));
                    }
                }
            }

            // Validate top level sum
            let sum_top: Rational32 = top_weights.iter().sum();
            if !(sum_top < Rational32::new(1, 1)) {
                return Err(MatterError::ValueError(format!(
                    "Invalid sith clause, top level weight sum must be >= 1. Got: {:?}",
                    sum_top
                )));
            }
        }

        // Calculate size based on weighted threshold
        let mut size = 0;
        for clause in &thold {
            for e in clause {
                match e {
                    WeightSpec::Simple(_) => {
                        size += 1;
                    }
                    WeightSpec::WeightedMap(_, nested_weights) => {
                        size += nested_weights.len();
                    }
                    WeightSpec::WeightedVec(nested_specs) => {
                        size += nested_specs.len();
                    }
                }
            }
        }

        // Create bexter string from thold
        let mut ta = Vec::new(); // List of clauses

        for clause in &thold {
            let mut bc = Vec::new(); // List of elements in current clause

            for e in clause {
                match e {
                    WeightSpec::Simple(weight) => {
                        // Format simple weight
                        let w_str =
                            if *weight > Rational32::new(0, 1) && *weight < Rational32::new(1, 1) {
                                format!("{}s{}", weight.numer(), weight.denom())
                            } else {
                                format!("{}", weight.numer() / weight.denom())
                            };

                        bc.push(w_str);
                    }
                    WeightSpec::WeightedMap(key_weight, nested_weights) => {
                        // Format key weight
                        let k = if *key_weight > Rational32::new(0, 1)
                            && *key_weight < Rational32::new(1, 1)
                        {
                            format!("{}s{}", key_weight.numer(), key_weight.denom())
                        } else {
                            format!("{}", key_weight.numer() / key_weight.denom())
                        };

                        // Format nested weights joined by 'v'
                        let v = nested_weights
                            .iter()
                            .map(|f| {
                                if *f > Rational32::new(0, 1) && *f < Rational32::new(1, 1) {
                                    format!("{}s{}", f.numer(), f.denom())
                                } else {
                                    format!("{}", f.numer() / f.denom())
                                }
                            })
                            .collect::<Vec<String>>()
                            .join("v");

                        // Join key and values with 'k'
                        let kv = format!("{}k{}", k, v);
                        bc.push(kv);
                    }
                    WeightSpec::WeightedVec(_nested_specs) => {
                        // Handle nested vectors similar to WeightedMap
                        // This would be more complex and depends on how you want to represent
                        // nested vectors in the bexter format
                        // For simplicity, just adding a placeholder
                        bc.push("1".to_string()); // Placeholder
                    }
                }
            }

            ta.push(bc);
        }

        // Join clauses with 'a' and elements with 'c'
        let bext = ta
            .iter()
            .map(|bc| bc.join("c"))
            .collect::<Vec<String>>()
            .join("a");

        // Create Bexter from bext
        let bexter = Bexter::from_bext(bext.as_bytes())?;

        // Update Tholder attributes
        self._weighted = true;
        self._size = size;
        self._sith = TholderSith::Weights(Vec::new()); // Should be derived from thold
        self._thold = TholderThold::Weighted(thold);
        self._bexter = Some(bexter);
        self._number = None;

        Ok(())
    }

    /// Add the missing ValueError to the MatterError enum
    #[allow(missing_docs)]
    pub fn weight(weight_str: &str) -> Result<Rational32, MatterError> {
        // Parse weight string into Rational32
        // Examples: "1/2", "1", "0", etc.

        if weight_str == "0" {
            return Ok(Rational32::new(0, 1));
        }

        if weight_str == "1" {
            return Ok(Rational32::new(1, 1));
        }

        if let Some(idx) = weight_str.find('/') {
            let numerator_str = &weight_str[0..idx];
            let denominator_str = &weight_str[idx + 1..];

            match (numerator_str.parse::<i32>(), denominator_str.parse::<i32>()) {
                (Ok(num), Ok(denom)) => {
                    if denom <= 0 {
                        return Err(MatterError::WeightError(format!(
                            "Denominator must be positive, got: {}",
                            denom
                        )));
                    }

                    let rational = Rational32::new(num, denom);

                    // Check that 0 <= rational <= 1
                    if rational < Rational32::new(0, 1) || rational > Rational32::new(1, 1) {
                        return Err(MatterError::WeightError(format!(
                            "Weight must be between 0 and 1, got: {}",
                            weight_str
                        )));
                    }

                    Ok(rational)
                }
                _ => Err(MatterError::ParseError(format!(
                    "Failed to parse rational number: {}",
                    weight_str
                ))),
            }
        } else {
            // Try to parse as an integer
            match weight_str.parse::<i32>() {
                Ok(num) => {
                    if num != 0 && num != 1 {
                        return Err(MatterError::WeightError(format!(
                            "Integer weight must be 0 or 1, got: {}",
                            num
                        )));
                    }

                    Ok(Rational32::new(num, 1))
                }
                Err(_) => Err(MatterError::ParseError(format!(
                    "Failed to parse weight: {}",
                    weight_str
                ))),
            }
        }
    }
}

impl fmt::Display for Tholder {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Tholder(weighted={}, size={})",
            self._weighted, self._size
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tholder_unweighted() {
        // Expected limen value
        let expected_limen = b"MAAL";

        // Create a Tholder with hex string "b" (which is 11 in decimal)
        let mut tholder = Tholder::default();
        tholder
            .process_sith(TholderSith::HexString("b".to_string()))
            .unwrap();

        // Check all properties and behaviors
        assert!(!tholder.weighted());

        let TholderThold::Integer(thold) = tholder.thold() else {
            panic!("Invalid threshold")
        };
        assert_eq!(tholder.size(), *thold);
        assert_eq!(*thold, 11);
        assert_eq!(tholder.limen(), expected_limen);

        let TholderSith::HexString(sith) = tholder.sith() else {
            panic!("Invalid sith")
        };
        assert_eq!(sith, "b");
        assert_eq!(tholder.json(), "\"b\"");
        assert_eq!(tholder.num().unwrap(), 11);

        // Test satisfaction with insufficient indices
        let insufficient_indices = vec![0, 1, 2];
        assert!(!tholder.satisfy(&insufficient_indices));

        // Test satisfaction with sufficient indices
        let sufficient_indices: Vec<usize> = (0..*thold).collect();
        assert!(tholder.satisfy(&sufficient_indices));
    }

    #[test]
    fn test_deserialize_weighted_sith_elements() -> Result<(), Box<dyn std::error::Error>> {
        // Test case 1: Simple array of fraction strings
        let json_str1 = r#"["1/2", "1/2", "1/4", "1/4", "1/4"]"#;
        let elements1: Vec<WeightedSithElement> = serde_json::from_str(json_str1)?;

        assert_eq!(elements1.len(), 5);
        if let WeightedSithElement::Simple(val) = &elements1[0] {
            assert_eq!(val, "1/2");
        } else {
            panic!("Expected Simple element");
        }

        // Test case 2: Nested arrays of weights
        let json_str2 = r#"[["1/2", "1/2", "1/4", "1/4", "1/4"], ["1", "1"]]"#;
        let elements2: Vec<Vec<WeightedSithElement>> = serde_json::from_str(json_str2)?;

        assert_eq!(elements2.len(), 2);
        assert_eq!(elements2[0].len(), 5);
        assert_eq!(elements2[1].len(), 2);

        if let WeightedSithElement::Simple(val) = &elements2[0][0] {
            assert_eq!(val, "1/2");
        } else {
            panic!("Expected Simple element");
        }

        if let WeightedSithElement::Simple(val) = &elements2[1][0] {
            assert_eq!(val, "1");
        } else {
            panic!("Expected Simple element");
        }

        // Test case 3: Mixed simple and complex elements
        let json_str3 = r#"[{"1/3":["1/2", "1/2", "1/2"]}, "1/3", "1/2", {"1/2": ["1", "1"]}]"#;
        let elements3: Vec<WeightedSithElement> = serde_json::from_str(json_str3)?;

        assert_eq!(elements3.len(), 4);

        // First element should be a Complex with "1/3" key
        match &elements3[0] {
            WeightedSithElement::Complex(map) => {
                assert_eq!(map.len(), 1);
                let values = map.get("1/3").expect("Key 1/3 should exist");
                assert_eq!(values.len(), 3);

                if let WeightedSithElement::Simple(val) = &values[0] {
                    assert_eq!(val, "1/2");
                } else {
                    panic!("Expected Simple element in complex map");
                }
            }
            _ => panic!("Expected Complex element"),
        }

        // Second element should be a Simple "1/3"
        if let WeightedSithElement::Simple(val) = &elements3[1] {
            assert_eq!(val, "1/3");
        } else {
            panic!("Expected Simple element");
        }

        // Third element should be a Simple "1/2"
        if let WeightedSithElement::Simple(val) = &elements3[2] {
            assert_eq!(val, "1/2");
        } else {
            panic!("Expected Simple element");
        }

        // Fourth element should be a Complex with "1/2" key
        match &elements3[3] {
            WeightedSithElement::Complex(map) => {
                assert_eq!(map.len(), 1);
                let values = map.get("1/2").expect("Key 1/2 should exist");
                assert_eq!(values.len(), 2);

                if let WeightedSithElement::Simple(val) = &values[0] {
                    assert_eq!(val, "1");
                } else {
                    panic!("Expected Simple element in complex map");
                }
            }
            _ => panic!("Expected Complex element"),
        }

        // Test case 4: Deeply nested structure with mixed types
        let json_str4 = r#"[[{"1/3":["1/2", "1/2", "1/2"]}, "1/2", {"1/2": ["1", "1"]}], ["1/2", {"1/2": ["1", "1"]}]]"#;
        let elements4: Vec<Vec<WeightedSithElement>> = serde_json::from_str(json_str4)?;

        assert_eq!(elements4.len(), 2);
        assert_eq!(elements4[0].len(), 3);
        assert_eq!(elements4[1].len(), 2);

        // First element of first array should be a Complex with "1/3" key
        match &elements4[0][0] {
            WeightedSithElement::Complex(map) => {
                assert_eq!(map.len(), 1);
                let values = map.get("1/3").expect("Key 1/3 should exist");
                assert_eq!(values.len(), 3);

                if let WeightedSithElement::Simple(val) = &values[0] {
                    assert_eq!(val, "1/2");
                } else {
                    panic!("Expected Simple element in complex map");
                }
            }
            _ => panic!("Expected Complex element"),
        }

        // Second element of first array should be a Simple "1/2"
        if let WeightedSithElement::Simple(val) = &elements4[0][1] {
            assert_eq!(val, "1/2");
        } else {
            panic!("Expected Simple element");
        }

        // Last element of second array should be a Complex with "1/2" key
        match &elements4[1][1] {
            WeightedSithElement::Complex(map) => {
                assert_eq!(map.len(), 1);
                let values = map.get("1/2").expect("Key 1/2 should exist");
                assert_eq!(values.len(), 2);

                if let WeightedSithElement::Simple(val) = &values[0] {
                    assert_eq!(val, "1");
                } else {
                    panic!("Expected Simple element in complex map");
                }
            }
            _ => panic!("Expected Complex element"),
        }

        // Additional test: validate we can parse nested Array elements
        let json_str5 = r#"["1/2", ["1/3", "1/3", "1/3"], "1/4"]"#;
        let elements5: Vec<WeightedSithElement> = serde_json::from_str(json_str5)?;

        assert_eq!(elements5.len(), 3);

        // Second element should be an Array
        match &elements5[1] {
            WeightedSithElement::Array(arr) => {
                assert_eq!(arr.len(), 3);
                if let WeightedSithElement::Simple(val) = &arr[0] {
                    assert_eq!(val, "1/3");
                } else {
                    panic!("Expected Simple element in array");
                }
            }
            _ => panic!("Expected Array element"),
        }

        // Verify weight parsing works for these elements
        if let WeightedSithElement::Simple(val) = &elements1[0] {
            let weight = Tholder::weight(val)?;
            assert_eq!(weight, Rational32::new(1, 2));
        }

        Ok(())
    }

    #[test]
    fn test_deserialize_json_bytes() -> Result<(), Box<dyn std::error::Error>> {
        // Test deserializing from JSON bytes
        let json_bytes = br#"["1/2", "1/2", "1/4", "1/4", "1/4"]"#;
        let elements: Vec<WeightedSithElement> = serde_json::from_slice(json_bytes)?;

        assert_eq!(elements.len(), 5);
        if let WeightedSithElement::Simple(val) = &elements[0] {
            assert_eq!(val, "1/2");
            let weight = Tholder::weight(val)?;
            assert_eq!(weight, Rational32::new(1, 2));
        } else {
            panic!("Expected Simple element");
        }

        // Test more complex structure from bytes
        let complex_json_bytes =
            br#"[{"1/3":["1/2", "1/2", "1/2"]}, "1/3", "1/2", {"1/2": ["1", "1"]}]"#;
        let complex_elements: Vec<WeightedSithElement> =
            serde_json::from_slice(complex_json_bytes)?;

        assert_eq!(complex_elements.len(), 4);

        // Verify the "1/3" key exists in the first element
        match &complex_elements[0] {
            WeightedSithElement::Complex(map) => {
                assert!(map.contains_key("1/3"));
                let values = map.get("1/3").unwrap();
                assert_eq!(values.len(), 3);
            }
            _ => panic!("Expected Complex element"),
        }

        Ok(())
    }

    // Optional: Add a helper to demonstrate a real world usage scenario
    #[test]
    fn test_process_weighted_sith() -> Result<(), Box<dyn std::error::Error>> {
        // This test simulates how these deserializations might be used in a real application

        let json_str = r#"["1/2", "1/2", "1/4", "1/4", "1/4"]"#;
        let elements: Vec<WeightedSithElement> = serde_json::from_str(json_str)?;

        // Calculate total weight (in a real application this might determine if a threshold is met)
        let mut total_weight = Rational32::new(0, 1);

        for element in &elements {
            if let WeightedSithElement::Simple(val) = element {
                total_weight = total_weight + Tholder::weight(val)?;
            }
        }

        // Verify the total weight is greater than 1 (which would satisfy a threshold in a real app)
        assert!(total_weight > Rational32::new(1, 1));
        assert_eq!(total_weight, Rational32::new(7, 4)); // 1/2 + 1/2 + 1/4 + 1/4 + 1/4 = 7/4

        Ok(())
    }

    // TODO: Add a test for Tholder::satisfy_indices()
    // #[test]
    fn test_tholder_weighted() -> Result<(), Box<dyn std::error::Error>> {
        // Create string array of weighted thresholds
        let json_str = r#"["1/2", "1/2", "1/4", "1/4", "1/4"]"#;
        let weights: Vec<WeightedSithElement> = serde_json::from_str(json_str)?;

        // Create Tholder with weighted threshold
        let tholder = Tholder::new(None, None, Some(TholderSith::Weights(weights)))?;

        // Verify the weighted flag
        assert!(tholder.weighted());
        assert_eq!(tholder.size(), 5);

        // Verify the parsed threshold structure
        if let TholderThold::Weighted(clauses) = tholder.thold() {
            // There should be one clause with 5 elements
            assert_eq!(clauses.len(), 1);
            assert_eq!(clauses[0].len(), 5);

            // Check the fraction values
            if let WeightSpec::Simple(fraction) = clauses[0][0] {
                assert_eq!(fraction, Rational32::new(1, 2));
            } else {
                panic!("Expected Simple weight spec for first element");
            }

            if let WeightSpec::Simple(fraction) = clauses[0][1] {
                assert_eq!(fraction, Rational32::new(1, 2));
            } else {
                panic!("Expected Simple weight spec for second element");
            }

            if let WeightSpec::Simple(fraction) = clauses[0][2] {
                assert_eq!(fraction, Rational32::new(1, 4));
            } else {
                panic!("Expected Simple weight spec for third element");
            }
        } else {
            panic!("Expected Weighted threshold type");
        }

        // Check the serialized limen
        assert_eq!(tholder.limen(), b"4AAFA1s2c1s2c1s4c1s4c1s4");

        // Verify sith representation
        // Note: This requires a properly implemented sith() method for weighted thresholds
        if let TholderSith::Weights(weights) = tholder.sith() {
            assert_eq!(weights.len(), 5);
            if let WeightedSithElement::Simple(s) = &weights[0] {
                assert_eq!(s, "1/2");
            } else {
                panic!("Expected Simple weight element");
            }
        } else {
            panic!("Expected Weights sith type");
        }

        // Verify JSON representation matches the input
        // This should return a JSON string representation of the threshold
        let expected_json = r#"["1/2","1/2","1/4","1/4","1/4"]"#;
        assert_eq!(tholder.json(), expected_json);

        // Verify numeric threshold is None for weighted thresholds
        assert_eq!(tholder.num(), None);

        // Now test the satisfy method with various signatures
        // This requires a functioning satisfy_weighted implementation

        // These should all satisfy the threshold (weights sum to ≥ 1)
        assert!(tholder.satisfy(&[0, 2, 4])); // 1/2 + 1/4 + 1/4 = 1
        assert!(tholder.satisfy(&[0, 1])); // 1/2 + 1/2 = 1
        assert!(tholder.satisfy(&[1, 3, 4])); // 1/2 + 1/4 + 1/4 = 1
        assert!(tholder.satisfy(&[0, 1, 2, 3, 4])); // All weights
        assert!(tholder.satisfy(&[3, 2, 0])); // 1/4 + 1/4 + 1/2 = 1
        assert!(tholder.satisfy(&[0, 0, 1, 2, 1])); // Duplicates should be ignored in calculation

        // These should not satisfy the threshold
        assert!(!tholder.satisfy(&[0, 2])); // 1/2 + 1/4 = 3/4 < 1
        assert!(!tholder.satisfy(&[2, 3, 4])); // 1/4 + 1/4 + 1/4 = 3/4 < 1

        Ok(())
    }
}
