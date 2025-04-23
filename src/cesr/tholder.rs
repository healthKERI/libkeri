use crate::cesr::bexter::Bexter;
use crate::cesr::number::Number;
use crate::cesr::{bex_dex, num_dex, BaseMatter, Parsable};
use crate::errors::MatterError;
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

    /// Complex weight with a fractional weight applied to a set of weights
    Complex(Rational32, Vec<Rational32>),
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

    /// Single clause of fractional weights
    SimpleWeights(Vec<WeightSithElement>),

    /// Multiple clauses of fractional weights (AND conditions)
    ComplexWeights(Vec<Vec<WeightSithElement>>),
}

/// Represents the different elements that can appear in a weight clause
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum WeightSithElement {
    /// Simple fraction string like "1/2"
    Simple(String),

    /// Complex weight with key as fraction and value as list of fractions
    Complex(String, HashMap<String, Vec<String>>),
}

/// Represents the parsed threshold for calculating satisfaction
#[derive(Debug, Clone)]
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
            let t = bexter.bext().replace('s', "/");

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

                        clause.push(ClauseItem::Weighted(Self::weight(k)?, weights));
                    } else {
                        clause.push(ClauseItem::Simple(Self::weight(e)?));
                    }
                }

                thold.push(clause);
            }

            // self.process_weighted(thold)?;
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

            TholderSith::SimpleWeights(weights) => {
                if weights.is_empty() {
                    return Err(MatterError::ValueError("Empty weight list".to_string()));
                }

                // Convert a single clause of weights
                let processed_clause = self.process_weight_clause(&weights)?;
                Err(MatterError::ValueError("NOT IMPLEMENTED".to_string()))
                // self.process_weighted(vec![processed_clause])
            }

            TholderSith::ComplexWeights(clauses) => {
                if clauses.is_empty() {
                    return Err(MatterError::ValueError("Empty weight list".to_string()));
                }

                // Convert all clauses
                let mut thold = Vec::new();
                for clause in clauses {
                    if clause.is_empty() {
                        return Err(MatterError::ValueError(
                            "Empty clause in weight list".to_string(),
                        ));
                    }

                    let processed_clause = self.process_weight_clause(&clause)?;
                    thold.push(processed_clause);
                }
                Err(MatterError::ValueError("NOT IMPLEMENTED".to_string()))
                // self.process_weighted(thold)
            }
        }
    }

    /// Helper function to process a clause of weight elements
    fn process_weight_clause(
        &self,
        clause: &[WeightSithElement],
    ) -> Result<Vec<ClauseItem>, MatterError> {
        let mut processed_clause = Vec::new();

        for element in clause {
            match element {
                WeightSithElement::Simple(weight_str) => {
                    let weight = Self::weight(weight_str)?;
                    processed_clause.push(ClauseItem::Simple(weight));
                }

                WeightSithElement::Complex(key, weights) => {
                    let key_weight = Self::weight(key)?;

                    let nested_weights: Result<Vec<Rational32>, _> =
                        weights.iter().map(|w| Self::weight("")).collect();

                    processed_clause.push(ClauseItem::Weighted(key_weight, nested_weights?));
                }
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
    fn satisfy_weighted(&self, indices: &[usize]) -> bool {
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
            TholderThold::Weighted(clauses) => {
                // Convert weighted threshold back to sith format
                // This is a simplified placeholder
                TholderSith::ComplexWeights(vec![]) // Would need actual implementation
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

    // Helper method to process JSON value into weighted threshold
    fn process_sith_from_json(json_val: serde_json::Value) -> Result<Self, MatterError> {
        match json_val {
            serde_json::Value::Array(arr) => {
                if arr.is_empty() {
                    return Err(MatterError::ValueError("Empty weight list".to_string()));
                }

                // Check if first element is an array (sequence of sequences)
                let is_nested = arr.iter().all(|v| v.is_array());

                if is_nested {
                    // Convert JSON array of arrays to TholderSith::ComplexWeights
                    let clauses = arr
                        .into_iter()
                        .map(|clause_val| {
                            match clause_val {
                                serde_json::Value::Array(clause_arr) => {
                                    // Convert each element in clause to WeightSithElement
                                    clause_arr
                                        .into_iter()
                                        .map(|elem| Self::json_value_to_weight_element(elem))
                                        .collect::<Result<Vec<_>, _>>()
                                }
                                _ => Err(MatterError::ValueError(format!(
                                    "Expected array of weights, got: {:?}",
                                    clause_val
                                ))),
                            }
                        })
                        .collect::<Result<Vec<Vec<WeightSithElement>>, _>>()?;

                    Self::process_weighted_clauses(clauses)
                } else {
                    // Convert JSON array to TholderSith::SimpleWeights
                    let weights = arr
                        .into_iter()
                        .map(|elem| Self::json_value_to_weight_element(elem))
                        .collect::<Result<Vec<_>, _>>()?;

                    // Wrap simple weights in a vector to make it a sequence of sequences
                    Self::process_weighted_clauses(vec![weights])
                }
            }
            _ => Err(MatterError::ValueError(format!(
                "Expected array of weights, got: {:?}",
                json_val
            ))),
        }
    }

    // Convert JSON value to WeightSithElement
    fn json_value_to_weight_element(
        value: serde_json::Value,
    ) -> Result<WeightSithElement, MatterError> {
        match value {
            serde_json::Value::String(s) => Ok(WeightSithElement::Simple(s)),
            serde_json::Value::Object(map) => {
                if map.len() != 1 {
                    return Err(MatterError::ValueError(format!(
                        "Nested weight map must have exactly one key-value pair, got: {:?}",
                        map
                    )));
                }

                let (key, val) = map.into_iter().next().unwrap();

                match val {
                    serde_json::Value::Array(arr) => {
                        let weights = arr
                            .into_iter()
                            .map(|v| match v {
                                serde_json::Value::String(s) => Ok(s),
                                _ => Err(MatterError::ValueError(format!(
                                    "Weight value must be a string, got: {:?}",
                                    v
                                ))),
                            })
                            .collect::<Result<Vec<String>, _>>()?;

                        let mut weight_map = HashMap::new();
                        weight_map.insert(key, weights);

                        Ok(WeightSithElement::Complex(String::from(""), weight_map))
                    }
                    _ => Err(MatterError::ValueError(format!(
                        "Weight value must be an array, got: {:?}",
                        val
                    ))),
                }
            }
            _ => Err(MatterError::ValueError(format!(
                "Weight element must be a string or object, got: {:?}",
                value
            ))),
        }
    }

    // Process weighted clauses
    fn process_weighted_clauses(clauses: Vec<Vec<WeightSithElement>>) -> Result<Self, MatterError> {
        // Convert string weights to actual Rational values
        let mut thold = Vec::new();

        for clause in clauses {
            let mut processed_clause = Vec::new();

            for element in clause {
                match element {
                    WeightSithElement::Simple(weight_str) => {
                        let weight = Self::weight(&weight_str)?;
                        processed_clause.push(WeightSpec::Simple(weight));
                    }
                    WeightSithElement::Complex(key, weight_map) => {
                        if weight_map.len() != 1 {
                            return Err(MatterError::ValueError(format!(
                                "Invalid nested weight map: {:?} - must have exactly one key",
                                weight_map
                            )));
                        }

                        let (key, values) = weight_map.into_iter().next().unwrap();
                        let key_weight = Self::weight(&key)?;

                        let value_weights = values
                            .into_iter()
                            .map(|v| Self::weight(&v))
                            .collect::<Result<Vec<_>, _>>()?;

                        processed_clause.push(WeightSpec::Complex(key_weight, value_weights));
                    }
                }
            }

            thold.push(processed_clause);
        }

        let mut tholder = Tholder::default();
        tholder.process_weighted(thold)?;

        Ok(tholder)
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

    // Process weighted threshold
    fn process_weighted(&mut self, thold: Vec<Vec<WeightSpec>>) -> Result<(), MatterError> {
        // Calculate size based on weighted threshold
        let size = 0;

        // TODO: Implement proper Bexter serialization of weighted threshold
        // This is a placeholder implementation
        let bexter = Bexter::from_qb64("B")?;

        self._weighted = true;
        self._size = size; // This should be calculated based on the threshold
        self._sith = TholderSith::ComplexWeights(vec![]); // This should be derived from thold
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

/// Represents an item in a threshold clause
#[derive(Debug, Clone)]
enum ClauseItem {
    /// Simple weight
    Simple(Rational32),
    /// Weighted threshold with key weight and list of witness weights
    Weighted(Rational32, Vec<Rational32>),
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
        // assert_eq!(tholder.size(), tholder.thold().);
        // assert_eq!(tholder.thold(), 11);
        assert_eq!(tholder.limen(), expected_limen);
        // assert_eq!(tholder.sith(), "b");
        assert_eq!(tholder.json(), "\"b\"");
        assert_eq!(tholder.num().unwrap(), 11);

        // Test satisfaction with insufficient indices
        let insufficient_indices = vec![0, 1, 2];
        assert!(!tholder.satisfy(&insufficient_indices));

        // Test satisfaction with sufficient indices
        // let sufficient_indices: Vec<usize> = (0..tholder.thold()).collect();
        // assert!(tholder.satisfy(&sufficient_indices));
    }
}
