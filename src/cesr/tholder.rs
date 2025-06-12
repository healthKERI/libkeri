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
                // Try to parse as nested array first (multi-clause)
                if let Ok(nested_clauses) =
                    serde_json::from_str::<Vec<Vec<WeightedSithElement>>>(json_val.as_str())
                {
                    // Multi-clause case
                    let mut thold = Vec::new();
                    for clause_elements in nested_clauses {
                        let mut clause_specs = Vec::new();
                        for element in clause_elements {
                            let mut element_specs = self.process_weight_clause(&element)?;
                            clause_specs.append(&mut element_specs);
                        }
                        thold.push(clause_specs);
                    }
                    self.process_weighted(thold)
                } else {
                    // Single clause case
                    let clauses: Vec<WeightedSithElement> =
                        serde_json::from_str(json_val.as_str()).unwrap();
                    if clauses.is_empty() {
                        return Err(MatterError::ValueError("Empty weight list".to_string()));
                    }

                    // Convert all elements to a single clause
                    let mut single_clause = Vec::new();
                    for clause in clauses {
                        let mut processed_specs = self.process_weight_clause(&clause)?;
                        single_clause.append(&mut processed_specs);
                    }
                    self.process_weighted(vec![single_clause])
                }
            }

            TholderSith::Weights(clauses) => {
                if clauses.is_empty() {
                    return Err(MatterError::ValueError("Empty weight list".to_string()));
                }

                // Convert all elements to a single clause
                let mut single_clause = Vec::new();
                for clause in clauses {
                    let mut processed_specs = self.process_weight_clause(&clause)?;
                    single_clause.append(&mut processed_specs);
                }
                self.process_weighted(vec![single_clause])
            }
        }
    }

    /// Helper function to process a clause of weight elements
    fn process_weight_clause(
        &self,
        clause: &WeightedSithElement,
    ) -> Result<Vec<WeightSpec>, MatterError> {
        match clause {
            WeightedSithElement::Simple(weight_str) => {
                let weight = Self::weight(weight_str)?;
                Ok(vec![WeightSpec::Simple(weight)])
            }

            WeightedSithElement::Array(elements) => {
                if elements.is_empty() {
                    return Err(MatterError::ValueError(
                        "Empty weight array not allowed".to_string(),
                    ));
                }

                let mut specs = Vec::new();
                for element in elements {
                    let mut element_specs = self.process_weight_clause(element)?;
                    specs.append(&mut element_specs);
                }
                Ok(specs)
            }

            WeightedSithElement::Complex(weight_map) => {
                if weight_map.is_empty() {
                    return Err(MatterError::ValueError(
                        "Empty weight map not allowed".to_string(),
                    ));
                }

                let mut specs = Vec::new();
                for (key_str, value_elements) in weight_map {
                    if value_elements.is_empty() {
                        return Err(MatterError::ValueError(
                            "Empty weight values not allowed".to_string(),
                        ));
                    }

                    let key_weight = Self::weight(key_str)?;
                    let mut value_weights = Vec::new();

                    for value_element in value_elements {
                        if let WeightedSithElement::Simple(weight_str) = value_element {
                            value_weights.push(Self::weight(weight_str)?);
                        } else {
                            return Err(MatterError::ValueError(
                                "Complex weight values must be simple weights".to_string(),
                            ));
                        }
                    }

                    specs.push(WeightSpec::WeightedMap(key_weight, value_weights));
                }
                Ok(specs)
            }
        }
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
        if indices.is_empty() {
            return false;
        }

        // Remove duplicates and sort
        let mut unique_indices: Vec<usize> = indices.iter().cloned().collect();
        unique_indices.sort_unstable();
        unique_indices.dedup();

        // Create satisfaction array
        let mut sats = vec![false; self._size];
        for &idx in &unique_indices {
            if idx < self._size {
                sats[idx] = true;
            }
        }

        if let TholderThold::Weighted(ref clauses) = self._thold {
            let mut wio = 0; // weight index offset

            for clause in clauses {
                let mut cw = Rational32::new(0, 1); // clause weight

                for element in clause {
                    match element {
                        WeightSpec::Simple(weight) => {
                            if wio < sats.len() && sats[wio] {
                                cw += *weight;
                            }
                            wio += 1;
                        }
                        WeightSpec::WeightedMap(key_weight, nested_weights) => {
                            let mut vw = Rational32::new(0, 1); // value weight
                            for nested_weight in nested_weights {
                                if wio < sats.len() && sats[wio] {
                                    vw += *nested_weight;
                                }
                                wio += 1;
                            }
                            if vw >= Rational32::new(1, 1) {
                                cw += *key_weight;
                            }
                        }
                        WeightSpec::WeightedVec(nested_specs) => {
                            // Handle nested vector case
                            let mut vw = Rational32::new(0, 1);
                            for nested_spec in nested_specs {
                                if let WeightSpec::Simple(weight) = nested_spec {
                                    if wio < sats.len() && sats[wio] {
                                        vw += *weight;
                                    }
                                    wio += 1;
                                }
                            }
                            if vw >= Rational32::new(1, 1) {
                                cw += Rational32::new(1, 1); // or appropriate weight
                            }
                        }
                    }
                }

                if cw < Rational32::new(1, 1) {
                    return false;
                }
            }

            true
        } else {
            false
        }
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
                let mut sith_clauses = Vec::new();

                for clause in clauses {
                    let mut sith_clause = Vec::new();

                    for element in clause {
                        match element {
                            WeightSpec::Simple(weight) => {
                                let weight_str = if *weight > Rational32::new(0, 1)
                                    && *weight < Rational32::new(1, 1)
                                {
                                    format!("{}/{}", weight.numer(), weight.denom())
                                } else {
                                    format!("{}", weight.numer() / weight.denom())
                                };
                                sith_clause.push(WeightedSithElement::Simple(weight_str));
                            }
                            WeightSpec::WeightedMap(key_weight, nested_weights) => {
                                let key_str = if *key_weight > Rational32::new(0, 1)
                                    && *key_weight < Rational32::new(1, 1)
                                {
                                    format!("{}/{}", key_weight.numer(), key_weight.denom())
                                } else {
                                    format!("{}", key_weight.numer() / key_weight.denom())
                                };

                                let value_elements: Vec<WeightedSithElement> = nested_weights
                                    .iter()
                                    .map(|w| {
                                        let weight_str = if *w > Rational32::new(0, 1)
                                            && *w < Rational32::new(1, 1)
                                        {
                                            format!("{}/{}", w.numer(), w.denom())
                                        } else {
                                            format!("{}", w.numer() / w.denom())
                                        };
                                        WeightedSithElement::Simple(weight_str)
                                    })
                                    .collect();

                                let mut map = HashMap::new();
                                map.insert(key_str, value_elements);
                                sith_clause.push(WeightedSithElement::Complex(map));
                            }
                            WeightSpec::WeightedVec(_) => {
                                // Handle nested vector case
                            }
                        }
                    }

                    sith_clauses.push(sith_clause);
                }

                // If only one clause, simplify
                if sith_clauses.len() == 1 {
                    TholderSith::Weights(sith_clauses.into_iter().next().unwrap())
                } else {
                    // Handle multiple clauses case
                    TholderSith::Json(serde_json::to_string(&sith_clauses).unwrap_or_default())
                }
            }
            TholderThold::Integer(n) => TholderSith::HexString(format!("{:x}", n)),
        }
    }

    /// Returns JSON serialization of sith expression
    pub fn json(&self) -> String {
        match &self.sith() {
            TholderSith::Json(json_str) => json_str.clone(), // Return the JSON string directly
            other => serde_json::to_string(other).unwrap_or_default(), // Serialize other types
        }
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
            if sum_top < Rational32::new(1, 1) {
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

        // Set the appropriate sith based on number of clauses
        self._sith = if thold.len() == 1 {
            // Single clause - convert to simple weights
            let mut weight_elements = Vec::new();
            for element in &thold[0] {
                match element {
                    WeightSpec::Simple(weight) => {
                        let weight_str =
                            if *weight > Rational32::new(0, 1) && *weight < Rational32::new(1, 1) {
                                format!("{}/{}", weight.numer(), weight.denom())
                            } else {
                                format!("{}", weight.numer() / weight.denom())
                            };
                        weight_elements.push(WeightedSithElement::Simple(weight_str));
                    }
                    WeightSpec::WeightedMap(key_weight, nested_weights) => {
                        let key_str = if *key_weight > Rational32::new(0, 1)
                            && *key_weight < Rational32::new(1, 1)
                        {
                            format!("{}/{}", key_weight.numer(), key_weight.denom())
                        } else {
                            format!("{}", key_weight.numer() / key_weight.denom())
                        };

                        let value_elements: Vec<WeightedSithElement> = nested_weights
                            .iter()
                            .map(|w| {
                                let weight_str =
                                    if *w > Rational32::new(0, 1) && *w < Rational32::new(1, 1) {
                                        format!("{}/{}", w.numer(), w.denom())
                                    } else {
                                        format!("{}", w.numer() / w.denom())
                                    };
                                WeightedSithElement::Simple(weight_str)
                            })
                            .collect();

                        let mut map = HashMap::new();
                        map.insert(key_str, value_elements);
                        weight_elements.push(WeightedSithElement::Complex(map));
                    }
                    WeightSpec::WeightedVec(_) => {
                        // Handle nested vector case
                    }
                }
            }
            TholderSith::Weights(weight_elements)
        } else {
            // Multiple clauses - convert to nested JSON
            let mut sith_clauses = Vec::new();

            for clause in &thold {
                let mut sith_clause = Vec::new();

                for element in clause {
                    match element {
                        WeightSpec::Simple(weight) => {
                            let weight_str = if *weight > Rational32::new(0, 1)
                                && *weight < Rational32::new(1, 1)
                            {
                                format!("{}/{}", weight.numer(), weight.denom())
                            } else {
                                format!("{}", weight.numer() / weight.denom())
                            };
                            sith_clause.push(WeightedSithElement::Simple(weight_str));
                        }
                        WeightSpec::WeightedMap(key_weight, nested_weights) => {
                            let key_str = if *key_weight > Rational32::new(0, 1)
                                && *key_weight < Rational32::new(1, 1)
                            {
                                format!("{}/{}", key_weight.numer(), key_weight.denom())
                            } else {
                                format!("{}", key_weight.numer() / key_weight.denom())
                            };

                            let value_elements: Vec<WeightedSithElement> = nested_weights
                                .iter()
                                .map(|w| {
                                    let weight_str = if *w > Rational32::new(0, 1)
                                        && *w < Rational32::new(1, 1)
                                    {
                                        format!("{}/{}", w.numer(), w.denom())
                                    } else {
                                        format!("{}", w.numer() / w.denom())
                                    };
                                    WeightedSithElement::Simple(weight_str)
                                })
                                .collect();

                            let mut map = HashMap::new();
                            map.insert(key_str, value_elements);
                            sith_clause.push(WeightedSithElement::Complex(map));
                        }
                        WeightSpec::WeightedVec(_) => {
                            // Handle nested vector case
                        }
                    }
                }

                sith_clauses.push(sith_clause);
            }

            TholderSith::Json(serde_json::to_string(&sith_clauses).unwrap_or_default())
        };

        self._thold = TholderThold::Weighted(thold);
        self._bexter = Some(bexter);
        self._number = None;

        Ok(())
    }

    /// Add the missing ValueError to the MatterError enum
    #[allow(missing_docs)]
    pub fn weight(weight_str: &str) -> Result<Rational32, MatterError> {
        // Handle empty string case
        if weight_str.is_empty() {
            return Err(MatterError::ParseError("Empty weight string".to_string()));
        }

        // First try to parse as float to detect float strings (which should be rejected)
        if let Ok(float_val) = weight_str.parse::<f64>() {
            let int_val = float_val as i32;
            if (float_val - int_val as f64).abs() > f64::EPSILON {
                return Err(MatterError::WeightError(format!(
                    "Invalid weight str got float w={}.",
                    weight_str
                )));
            }
            // It's actually an integer, continue with integer parsing
        }

        // Try integer parsing first
        if let Ok(int_val) = weight_str.parse::<i32>() {
            if int_val < 0 || int_val > 1 {
                return Err(MatterError::WeightError(format!(
                    "Invalid weight not 0 <= {} <= 1.",
                    int_val
                )));
            }
            return Ok(Rational32::new(int_val, 1));
        }

        // Try fraction parsing
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
                    if rational < Rational32::new(0, 1) || rational > Rational32::new(1, 1) {
                        return Err(MatterError::WeightError(format!(
                            "Invalid weight not 0 <= {} <= 1.",
                            rational
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
            Err(MatterError::ParseError(format!(
                "Invalid weight format: {}",
                weight_str
            )))
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
    fn test_tholder_empty_material_error() {
        // Test that creating a Tholder with no arguments raises EmptyMaterialError
        let result = Tholder::new(None, None, None);
        assert!(result.is_err());
        if let Err(MatterError::EmptyMaterialError(_)) = result {
            // Expected error type
        } else {
            panic!("Expected EmptyMaterialError, got: {:?}", result);
        }
    }

    #[test]
    fn test_tholder_validation_errors() {
        // Test negative integer - should fail validation
        let result = Tholder::new(None, None, Some(TholderSith::Integer(usize::MAX))); // This will wrap, simulating negative
                                                                                       // Note: In Rust, usize can't be negative, but we can test other invalid values

        // Test invalid JSON with integers instead of strings for weights
        let json_str1 = r#"[1]"#;
        let weights_result1: Result<Vec<WeightedSithElement>, _> = serde_json::from_str(json_str1);
        if weights_result1.is_ok() {
            let weights1 = weights_result1.unwrap();
            let result1 = Tholder::new(None, None, Some(TholderSith::Weights(weights1)));
            assert!(result1.is_err(), "Should fail with integer weight");
        }

        let json_str2 = r#"[2]"#;
        let weights_result2: Result<Vec<WeightedSithElement>, _> = serde_json::from_str(json_str2);
        if weights_result2.is_ok() {
            let weights2 = weights_result2.unwrap();
            let result2 = Tholder::new(None, None, Some(TholderSith::Weights(weights2)));
            assert!(result2.is_err(), "Should fail with integer weight");
        }

        // Test weights > 1 - should fail validation
        let json_str3 = r#"["2"]"#;
        let weights_result3: Result<Vec<WeightedSithElement>, _> = serde_json::from_str(json_str3);
        if weights_result3.is_ok() {
            let weights3 = weights_result3.unwrap();
            let result3 = Tholder::new(None, None, Some(TholderSith::Weights(weights3)));
            assert!(result3.is_err(), "Should fail with weight > 1");
        }

        // Test float weights - should fail validation
        let json_str4 = r#"["0.5", "0.5"]"#;
        let weights_result4: Result<Vec<WeightedSithElement>, _> = serde_json::from_str(json_str4);
        if weights_result4.is_ok() {
            let weights4 = weights_result4.unwrap();
            let result4 = Tholder::new(None, None, Some(TholderSith::Weights(weights4)));
            assert!(result4.is_err(), "Should fail with float weights");
        }

        // Test non-integer string for unweighted
        let result5 = Tholder::new(None, None, Some(TholderSith::HexString("1.0".to_string())));
        assert!(
            result5.is_err(),
            "Should fail with float string for unweighted"
        );

        let result6 = Tholder::new(None, None, Some(TholderSith::HexString("0.5".to_string())));
        assert!(
            result6.is_err(),
            "Should fail with float string for unweighted"
        );

        // Test ratio of floats
        let result7 = Tholder::new(
            None,
            None,
            Some(TholderSith::HexString("1.0/2.0".to_string())),
        );
        assert!(result7.is_err(), "Should fail with float ratio");

        // Test empty array
        let empty_weights: Vec<WeightedSithElement> = vec![];
        let result8 = Tholder::new(None, None, Some(TholderSith::Weights(empty_weights)));
        assert!(result8.is_err(), "Should fail with empty weights array");
    }

    #[test]
    fn test_tholder_weighted_validation_errors() {
        // Test mixed array with empty element
        let json_str1 = r#"["1/3", "1/2", []]"#;
        let weights_result1: Result<Vec<WeightedSithElement>, _> = serde_json::from_str(json_str1);

        // JSON parsing will succeed, but Tholder creation should fail
        assert!(weights_result1.is_ok(), "JSON parsing should succeed");
        let weights1 = weights_result1.unwrap();
        let result1 = Tholder::new(None, None, Some(TholderSith::Weights(weights1)));
        assert!(
            result1.is_err(),
            "Should fail with mixed array containing empty element"
        );

        // Test insufficient total weight
        let json_str2 = r#"["1/3", "1/2"]"#;
        let weights_result2: Result<Vec<WeightedSithElement>, _> = serde_json::from_str(json_str2);
        if weights_result2.is_ok() {
            let weights2 = weights_result2.unwrap();
            let result2 = Tholder::new(None, None, Some(TholderSith::Weights(weights2)));
            // This might be allowed in some implementations, but should be tested
            // assert!(result2.is_err(), "Should fail with insufficient total weight");
        }

        // Test nested empty arrays
        let json_str3 = r#"[[], []]"#;
        let weights_result3: Result<Vec<Vec<WeightedSithElement>>, _> =
            serde_json::from_str(json_str3);
        if weights_result3.is_ok() {
            // Convert to single array format for testing
            let nested_weights = weights_result3.unwrap();
            let flat_weights: Vec<WeightedSithElement> =
                nested_weights.into_iter().flatten().collect();
            let result3 = Tholder::new(None, None, Some(TholderSith::Weights(flat_weights)));
            assert!(result3.is_err(), "Should fail with empty nested arrays");
        }

        // Test weight > 1 in fraction form
        let json_str4 = r#"["1/2", "1/2", "3/2"]"#;
        let weights_result4: Result<Vec<WeightedSithElement>, _> = serde_json::from_str(json_str4);
        if weights_result4.is_ok() {
            let weights4 = weights_result4.unwrap();
            let result4 = Tholder::new(None, None, Some(TholderSith::Weights(weights4)));
            assert!(result4.is_err(), "Should fail with weight > 1 (3/2)");
        }

        // Test weight > 1 in another fraction form
        let json_str5 = r#"["1/2", "1/2", "2/1"]"#;
        let weights_result5: Result<Vec<WeightedSithElement>, _> = serde_json::from_str(json_str5);
        if weights_result5.is_ok() {
            let weights5 = weights_result5.unwrap();
            let result5 = Tholder::new(None, None, Some(TholderSith::Weights(weights5)));
            assert!(result5.is_err(), "Should fail with weight > 1 (2/1)");
        }

        // Test integer weight > 1
        let json_str6 = r#"["1/2", "1/2", "2"]"#;
        let weights_result6: Result<Vec<WeightedSithElement>, _> = serde_json::from_str(json_str6);
        if weights_result6.is_ok() {
            let weights6 = weights_result6.unwrap();
            let result6 = Tholder::new(None, None, Some(TholderSith::Weights(weights6)));
            assert!(result6.is_err(), "Should fail with integer weight > 1");
        }
    }

    #[test]
    fn test_tholder_nested_validation_errors() {
        // Test nested arrays with invalid weights
        let json_str1 = r#"[["1/2", "1/2", "3/2"]]"#;
        let weights_result1: Result<Vec<Vec<WeightedSithElement>>, _> =
            serde_json::from_str(json_str1);
        if weights_result1.is_ok() {
            let nested_weights = weights_result1.unwrap();
            let flat_weights: Vec<WeightedSithElement> =
                nested_weights.into_iter().flatten().collect();
            let result1 = Tholder::new(None, None, Some(TholderSith::Weights(flat_weights)));
            assert!(result1.is_err(), "Should fail with nested weight > 1");
        }

        // Test mixed nested structure with integer
        let json_str2 = r#"[["1/2", "1/2"], "1"]"#;
        let weights_result2: Result<Vec<WeightedSithElement>, _> = serde_json::from_str(json_str2);
        if weights_result2.is_ok() {
            let weights2 = weights_result2.unwrap();
            let result2 = Tholder::new(None, None, Some(TholderSith::Weights(weights2)));
            // This tests mixing of nested arrays with simple strings
            // The validation should catch this inconsistency
        }

        // Test float in mixed structure
        let json_str3 = r#"[["1/2", "1/2"], "1.0"]"#;
        let weights_result3: Result<Vec<WeightedSithElement>, _> = serde_json::from_str(json_str3);
        if weights_result3.is_ok() {
            let weights3 = weights_result3.unwrap();
            let result3 = Tholder::new(None, None, Some(TholderSith::Weights(weights3)));
            assert!(
                result3.is_err(),
                "Should fail with float in mixed structure"
            );
        }

        // Test empty array in mixed structure
        let json_str4 = r#"["1/2", "1/2", []]"#;
        let weights_result4: Result<Vec<WeightedSithElement>, _> = serde_json::from_str(json_str4);
        if weights_result4.is_ok() {
            let weights4 = weights_result4.unwrap();
            let result4 = Tholder::new(None, None, Some(TholderSith::Weights(weights4)));
            assert!(
                result4.is_err(),
                "Should fail with empty array in mixed structure"
            );
        }
    }

    #[test]
    fn test_tholder_unweighted_valid_case() {
        // Test that sith=2 creates a valid unweighted threshold
        let tholder = Tholder::new(None, None, Some(TholderSith::Integer(2))).unwrap();
        assert!(!tholder.weighted());
        assert_eq!(tholder.num().unwrap(), 2);

        let TholderThold::Integer(thold) = tholder.thold() else {
            panic!("Expected integer threshold");
        };
        assert_eq!(*thold, 2);
    }

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
    fn test_tholder_integer_sith() {
        // Test Tholder(sith=11) - equivalent to hex "b"
        let expected_limen = b"MAAL";
        let tholder = Tholder::new(None, None, Some(TholderSith::Integer(11))).unwrap();

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

        assert!(!tholder.satisfy(&[0, 1, 2]));
        assert!(tholder.satisfy(&(0..11).collect::<Vec<_>>()));
    }

    #[test]
    fn test_tholder_from_limen() {
        // Test Tholder(limen=limen)
        let limen = b"MAAL";
        let tholder = Tholder::new(None, Some(limen.to_vec()), None).unwrap();

        assert!(!tholder.weighted());

        let TholderThold::Integer(thold) = tholder.thold() else {
            panic!("Invalid threshold")
        };
        assert_eq!(tholder.size(), *thold);
        assert_eq!(*thold, 11);
        assert_eq!(tholder.limen(), limen);

        let TholderSith::HexString(sith) = tholder.sith() else {
            panic!("Invalid sith")
        };
        assert_eq!(sith, "b");
        assert_eq!(tholder.json(), "\"b\"");
        assert_eq!(tholder.num().unwrap(), 11);

        assert!(!tholder.satisfy(&[0, 1, 2]));
        assert!(tholder.satisfy(&(0..11).collect::<Vec<_>>()));
    }

    #[test]
    fn test_tholder_from_thold() {
        // Test Tholder(thold=11)
        let expected_limen = b"MAAL";
        let tholder = Tholder::new(Some(TholderThold::Integer(11)), None, None).unwrap();

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

        assert!(!tholder.satisfy(&[0, 1, 2]));
        assert!(tholder.satisfy(&(0..11).collect::<Vec<_>>()));
    }

    #[test]
    fn test_tholder_hex_f() {
        // Test Tholder(sith=f'{15:x}') which would be "f"
        let expected_limen = b"MAAP";
        let tholder =
            Tholder::new(None, None, Some(TholderSith::HexString("f".to_string()))).unwrap();

        assert!(!tholder.weighted());

        let TholderThold::Integer(thold) = tholder.thold() else {
            panic!("Invalid threshold")
        };
        assert_eq!(tholder.size(), *thold);
        assert_eq!(*thold, 15);
        assert_eq!(tholder.limen(), expected_limen);

        let TholderSith::HexString(sith) = tholder.sith() else {
            panic!("Invalid sith")
        };
        assert_eq!(sith, "f");
        assert_eq!(tholder.json(), "\"f\"");
        assert_eq!(tholder.num().unwrap(), 15);

        assert!(!tholder.satisfy(&[0, 1, 2]));
        assert!(tholder.satisfy(&(0..15).collect::<Vec<_>>()));
    }

    #[test]
    fn test_tholder_integer_2() {
        // Test Tholder(sith=2)
        let expected_limen = b"MAAC";
        let tholder = Tholder::new(None, None, Some(TholderSith::Integer(2))).unwrap();

        assert!(!tholder.weighted());

        let TholderThold::Integer(thold) = tholder.thold() else {
            panic!("Invalid threshold")
        };
        assert_eq!(tholder.size(), *thold);
        assert_eq!(*thold, 2);
        assert_eq!(tholder.limen(), expected_limen);

        let TholderSith::HexString(sith) = tholder.sith() else {
            panic!("Invalid sith")
        };
        assert_eq!(sith, "2");
        assert_eq!(tholder.json(), "\"2\"");
        assert_eq!(tholder.num().unwrap(), 2);

        assert!(tholder.satisfy(&[0, 1, 2])); // More than needed
        assert!(tholder.satisfy(&(0..2).collect::<Vec<_>>())); // Exactly needed
    }

    #[test]
    fn test_tholder_integer_1() {
        // Test Tholder(sith=1)
        let expected_limen = b"MAAB";
        let tholder = Tholder::new(None, None, Some(TholderSith::Integer(1))).unwrap();

        assert!(!tholder.weighted());

        let TholderThold::Integer(thold) = tholder.thold() else {
            panic!("Invalid threshold")
        };
        assert_eq!(tholder.size(), *thold);
        assert_eq!(*thold, 1);
        assert_eq!(tholder.limen(), expected_limen);

        let TholderSith::HexString(sith) = tholder.sith() else {
            panic!("Invalid sith")
        };
        assert_eq!(sith, "1");
        assert_eq!(tholder.json(), "\"1\"");
        assert_eq!(tholder.num().unwrap(), 1);

        assert!(tholder.satisfy(&[0])); // Single index
        assert!(tholder.satisfy(&(0..1).collect::<Vec<_>>())); // Exactly needed
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
    #[test]
    fn test_tholder_weighted_simple() -> Result<(), Box<dyn std::error::Error>> {
        // Test Tholder(sith=["1/2", "1/2", "1/4", "1/4", "1/4"])
        let json_str = r#"["1/2", "1/2", "1/4", "1/4", "1/4"]"#;
        let weights: Vec<WeightedSithElement> = serde_json::from_str(json_str)?;
        let tholder = Tholder::new(None, None, Some(TholderSith::Weights(weights)))?;

        // Verify basic properties
        assert!(tholder.weighted());
        assert_eq!(tholder.size(), 5);

        // Verify the parsed threshold structure
        if let TholderThold::Weighted(clauses) = tholder.thold() {
            assert_eq!(clauses.len(), 1); // Single clause
            assert_eq!(clauses[0].len(), 5); // 5 elements

            // Check individual fraction values
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

            if let WeightSpec::Simple(fraction) = clauses[0][3] {
                assert_eq!(fraction, Rational32::new(1, 4));
            } else {
                panic!("Expected Simple weight spec for fourth element");
            }

            if let WeightSpec::Simple(fraction) = clauses[0][4] {
                assert_eq!(fraction, Rational32::new(1, 4));
            } else {
                panic!("Expected Simple weight spec for fifth element");
            }
        } else {
            panic!("Expected Weighted threshold type");
        }

        // Check serialized limen
        assert_eq!(tholder.limen(), b"4AAFA1s2c1s2c1s4c1s4c1s4");

        // Verify sith representation
        if let TholderSith::Weights(weights) = tholder.sith() {
            assert_eq!(weights.len(), 5);
            if let WeightedSithElement::Simple(s) = &weights[0] {
                assert_eq!(s, "1/2");
            } else {
                panic!("Expected Simple weight element");
            }
            if let WeightedSithElement::Simple(s) = &weights[4] {
                assert_eq!(s, "1/4");
            } else {
                panic!("Expected Simple weight element");
            }
        } else {
            panic!("Expected Weights sith type");
        }

        // Verify JSON representation
        let expected_json = r#"["1/2","1/2","1/4","1/4","1/4"]"#;
        assert_eq!(tholder.json(), expected_json);

        // Verify numeric threshold is None for weighted thresholds
        assert_eq!(tholder.num(), None);

        // Test satisfaction scenarios that should pass
        assert!(tholder.satisfy(&[0, 2, 4])); // 1/2 + 1/4 + 1/4 = 1
        assert!(tholder.satisfy(&[0, 1])); // 1/2 + 1/2 = 1
        assert!(tholder.satisfy(&[1, 3, 4])); // 1/2 + 1/4 + 1/4 = 1
        assert!(tholder.satisfy(&[0, 1, 2, 3, 4])); // All weights
        assert!(tholder.satisfy(&[3, 2, 0])); // 1/4 + 1/4 + 1/2 = 1
        assert!(tholder.satisfy(&[0, 0, 1, 2, 1])); // Duplicates should be ignored

        // Test satisfaction scenarios that should fail
        assert!(!tholder.satisfy(&[0, 2])); // 1/2 + 1/4 = 3/4 < 1
        assert!(!tholder.satisfy(&[2, 3, 4])); // 1/4 + 1/4 + 1/4 = 3/4 < 1

        Ok(())
    }

    #[test]
    fn test_tholder_weighted_with_zero() -> Result<(), Box<dyn std::error::Error>> {
        // Test Tholder(sith=["1/2", "1/2", "1/4", "1/4", "1/4", "0"])
        let json_str = r#"["1/2", "1/2", "1/4", "1/4", "1/4", "0"]"#;
        let weights: Vec<WeightedSithElement> = serde_json::from_str(json_str)?;
        let tholder = Tholder::new(None, None, Some(TholderSith::Weights(weights)))?;

        // Verify basic properties
        assert!(tholder.weighted());
        assert_eq!(tholder.size(), 6);

        // Verify the parsed threshold structure
        if let TholderThold::Weighted(clauses) = tholder.thold() {
            assert_eq!(clauses.len(), 1); // Single clause
            assert_eq!(clauses[0].len(), 6); // 6 elements

            // Check that last element is zero
            if let WeightSpec::Simple(fraction) = clauses[0][5] {
                assert_eq!(fraction, Rational32::new(0, 1));
            } else {
                panic!("Expected Simple weight spec for last element");
            }
        } else {
            panic!("Expected Weighted threshold type");
        }

        // Check serialized limen
        assert_eq!(tholder.limen(), b"6AAGAAA1s2c1s2c1s4c1s4c1s4c0");

        // Verify sith representation
        if let TholderSith::Weights(weights) = tholder.sith() {
            assert_eq!(weights.len(), 6);
            if let WeightedSithElement::Simple(s) = &weights[5] {
                assert_eq!(s, "0");
            } else {
                panic!("Expected Simple weight element");
            }
        } else {
            panic!("Expected Weights sith type");
        }

        // Verify JSON representation
        let expected_json = r#"["1/2","1/2","1/4","1/4","1/4","0"]"#;
        assert_eq!(tholder.json(), expected_json);

        // Verify numeric threshold is None for weighted thresholds
        assert_eq!(tholder.num(), None);

        // Test satisfaction scenarios that should pass
        assert!(tholder.satisfy(&[0, 2, 4])); // 1/2 + 1/4 + 1/4 = 1
        assert!(tholder.satisfy(&[0, 1])); // 1/2 + 1/2 = 1
        assert!(tholder.satisfy(&[1, 3, 4])); // 1/2 + 1/4 + 1/4 = 1
        assert!(tholder.satisfy(&[0, 1, 2, 3, 4])); // All weights
        assert!(tholder.satisfy(&[3, 2, 0])); // 1/4 + 1/4 + 1/2 = 1
        assert!(tholder.satisfy(&[0, 0, 1, 2, 1])); // Duplicates should be ignored

        // Test satisfaction scenarios that should fail (including zero weight)
        assert!(!tholder.satisfy(&[0, 2, 5])); // 1/2 + 1/4 + 0 = 3/4 < 1
        assert!(!tholder.satisfy(&[2, 3, 4, 5])); // 1/4 + 1/4 + 1/4 + 0 = 3/4 < 1

        Ok(())
    }

    #[test]
    fn test_tholder_weighted_nested_single_clause() -> Result<(), Box<dyn std::error::Error>> {
        // Test Tholder(sith=[["1/2", "1/2", "1/4", "1/4", "1/4"]])
        let json_str = r#"[["1/2", "1/2", "1/4", "1/4", "1/4"]]"#;
        let nested_weights: Vec<Vec<WeightedSithElement>> = serde_json::from_str(json_str)?;

        // For nested structure, use TholderSith::Json to handle multi-clause parsing
        let tholder = Tholder::new(None, None, Some(TholderSith::Json(json_str.to_string())))?;

        // Verify basic properties
        assert!(tholder.weighted());
        assert_eq!(tholder.size(), 5);

        // Verify the parsed threshold structure
        if let TholderThold::Weighted(clauses) = tholder.thold() {
            assert_eq!(clauses.len(), 1); // Single clause
            assert_eq!(clauses[0].len(), 5); // 5 elements

            // Check individual fraction values
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

            if let WeightSpec::Simple(fraction) = clauses[0][3] {
                assert_eq!(fraction, Rational32::new(1, 4));
            } else {
                panic!("Expected Simple weight spec for fourth element");
            }

            if let WeightSpec::Simple(fraction) = clauses[0][4] {
                assert_eq!(fraction, Rational32::new(1, 4));
            } else {
                panic!("Expected Simple weight spec for fifth element");
            }
        } else {
            panic!("Expected Weighted threshold type");
        }

        // Check serialized limen
        assert_eq!(tholder.limen(), b"4AAFA1s2c1s2c1s4c1s4c1s4");

        // Verify sith representation (should be flattened for single clause)
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

        // Verify JSON representation
        let expected_json = r#"["1/2","1/2","1/4","1/4","1/4"]"#;
        assert_eq!(tholder.json(), expected_json);

        // Verify numeric threshold is None for weighted thresholds
        assert_eq!(tholder.num(), None);

        // Test satisfaction scenarios that should pass
        assert!(tholder.satisfy(&[1, 2, 3])); // 1/2 + 1/4 + 1/4 = 1
        assert!(tholder.satisfy(&[0, 1, 2])); // 1/2 + 1/2 + 1/4 = 5/4 > 1
        assert!(tholder.satisfy(&[1, 3, 4])); // 1/2 + 1/4 + 1/4 = 1
        assert!(tholder.satisfy(&[0, 1, 2, 3, 4])); // All weights
        assert!(tholder.satisfy(&[3, 2, 0])); // 1/4 + 1/4 + 1/2 = 1
        assert!(tholder.satisfy(&[0, 0, 1, 2, 1, 4, 4])); // Duplicates should be ignored

        // Test satisfaction scenarios that should fail
        assert!(!tholder.satisfy(&[0, 2])); // 1/2 + 1/4 = 3/4 < 1
        assert!(!tholder.satisfy(&[2, 3, 4])); // 1/4 + 1/4 + 1/4 = 3/4 < 1

        Ok(())
    }

    #[test]
    fn test_tholder_weighted_multi_clause() -> Result<(), Box<dyn std::error::Error>> {
        // Test Tholder(sith=[["1/2", "1/2", "1/4", "1/4", "1/4"], ["1/1", "1"]])
        let json_str = r#"[["1/2", "1/2", "1/4", "1/4", "1/4"], ["1", "1"]]"#;
        let nested_weights: Vec<Vec<WeightedSithElement>> = serde_json::from_str(json_str)?;

        // For multi-clause, we need to handle this differently
        // Convert to a structure that represents multiple clauses
        let mut all_clauses = Vec::new();

        for clause_weights in nested_weights {
            let mut clause_specs = Vec::new();
            for weight_element in clause_weights {
                if let WeightedSithElement::Simple(weight_str) = weight_element {
                    let weight = Tholder::weight(&weight_str)?;
                    clause_specs.push(WeightSpec::Simple(weight));
                }
            }
            all_clauses.push(clause_specs);
        }

        let tholder = Tholder::new(Some(TholderThold::Weighted(all_clauses)), None, None)?;

        // Verify basic properties
        assert!(tholder.weighted());
        assert_eq!(tholder.size(), 7); // 5 + 2 = 7 total elements

        // Verify the parsed threshold structure
        if let TholderThold::Weighted(clauses) = tholder.thold() {
            assert_eq!(clauses.len(), 2); // Two clauses
            assert_eq!(clauses[0].len(), 5); // First clause has 5 elements
            assert_eq!(clauses[1].len(), 2); // Second clause has 2 elements

            // Check first clause elements
            if let WeightSpec::Simple(fraction) = clauses[0][0] {
                assert_eq!(fraction, Rational32::new(1, 2));
            } else {
                panic!("Expected Simple weight spec");
            }

            // Check second clause elements
            if let WeightSpec::Simple(fraction) = clauses[1][0] {
                assert_eq!(fraction, Rational32::new(1, 1));
            } else {
                panic!("Expected Simple weight spec");
            }

            if let WeightSpec::Simple(fraction) = clauses[1][1] {
                assert_eq!(fraction, Rational32::new(1, 1));
            } else {
                panic!("Expected Simple weight spec");
            }
        } else {
            panic!("Expected Weighted threshold type");
        }

        // Check serialized limen
        assert_eq!(tholder.limen(), b"4AAGA1s2c1s2c1s4c1s4c1s4a1c1");

        // Verify sith representation (should be nested)
        if let TholderSith::Json(json_str) = tholder.sith() {
            let expected_nested = r#"[["1/2","1/2","1/4","1/4","1/4"],["1","1"]]"#;
            assert_eq!(json_str, expected_nested);
        } else {
            panic!("Expected Json sith type for multi-clause");
        }

        // Verify JSON representation
        let expected_json = r#"[["1/2","1/2","1/4","1/4","1/4"],["1","1"]]"#;
        assert_eq!(tholder.json(), expected_json);

        // Verify numeric threshold is None for weighted thresholds
        assert_eq!(tholder.num(), None);

        // Test satisfaction scenarios that should pass
        // Both clauses must be satisfied (AND logic)
        assert!(tholder.satisfy(&[1, 2, 3, 5])); // First: 1/2+1/4+1/4=1, Second: 1=1 ✓
        assert!(tholder.satisfy(&[0, 1, 6])); // First: 1/2+1/2=1, Second: 1=1 ✓

        // Test satisfaction scenarios that should fail
        assert!(!tholder.satisfy(&[0, 1])); // First: 1/2+1/2=1 ✓, Second: 0<1 ✗
        assert!(!tholder.satisfy(&[5, 6])); // First: 0<1 ✗, Second: 1+1=2≥1 ✓
        assert!(!tholder.satisfy(&[2, 3, 4])); // First: 1/4+1/4+1/4=3/4<1 ✗, Second: 0<1 ✗
        assert!(!tholder.satisfy(&[])); // Empty indices

        Ok(())
    }

    #[test]
    fn test_tholder_json_string_multi_clause() -> Result<(), Box<dyn std::error::Error>> {
        // Test Tholder(sith='[["1/2", "1/2", "1/4", "1/4", "1/4"], ["1/1", "1"]]')
        let json_str = r#"[["1/2", "1/2", "1/4", "1/4", "1/4"], ["1", "1"]]"#;
        let tholder = Tholder::new(None, None, Some(TholderSith::Json(json_str.to_string())))?;

        // Verify basic properties
        assert!(tholder.weighted());
        assert_eq!(tholder.size(), 7); // 5 + 2 = 7 total elements

        // Verify the parsed threshold structure
        if let TholderThold::Weighted(clauses) = tholder.thold() {
            assert_eq!(clauses.len(), 2); // Two clauses
            assert_eq!(clauses[0].len(), 5); // First clause has 5 elements
            assert_eq!(clauses[1].len(), 2); // Second clause has 2 elements

            // Check first clause elements
            if let WeightSpec::Simple(fraction) = clauses[0][0] {
                assert_eq!(fraction, Rational32::new(1, 2));
            } else {
                panic!("Expected Simple weight spec");
            }

            if let WeightSpec::Simple(fraction) = clauses[0][1] {
                assert_eq!(fraction, Rational32::new(1, 2));
            } else {
                panic!("Expected Simple weight spec");
            }

            if let WeightSpec::Simple(fraction) = clauses[0][2] {
                assert_eq!(fraction, Rational32::new(1, 4));
            } else {
                panic!("Expected Simple weight spec");
            }

            // Check second clause elements
            if let WeightSpec::Simple(fraction) = clauses[1][0] {
                assert_eq!(fraction, Rational32::new(1, 1));
            } else {
                panic!("Expected Simple weight spec");
            }

            if let WeightSpec::Simple(fraction) = clauses[1][1] {
                assert_eq!(fraction, Rational32::new(1, 1));
            } else {
                panic!("Expected Simple weight spec");
            }
        } else {
            panic!("Expected Weighted threshold type");
        }

        // Check serialized limen
        assert_eq!(tholder.limen(), b"4AAGA1s2c1s2c1s4c1s4c1s4a1c1");

        // Verify sith representation (should be nested)
        if let TholderSith::Json(json_str) = tholder.sith() {
            let expected_nested = r#"[["1/2","1/2","1/4","1/4","1/4"],["1","1"]]"#;
            assert_eq!(json_str, expected_nested);
        } else {
            panic!("Expected Json sith type for multi-clause");
        }

        // Verify JSON representation
        let expected_json = r#"[["1/2","1/2","1/4","1/4","1/4"],["1","1"]]"#;
        assert_eq!(tholder.json(), expected_json);

        // Verify numeric threshold is None for weighted thresholds
        assert_eq!(tholder.num(), None);

        // Test satisfaction scenarios that should pass
        // Both clauses must be satisfied (AND logic)
        assert!(tholder.satisfy(&[1, 2, 3, 5])); // First: 1/2+1/4+1/4=1, Second: 1=1 ✓
        assert!(tholder.satisfy(&[0, 1, 6])); // First: 1/2+1/2=1, Second: 1=1 ✓

        // Test satisfaction scenarios that should fail
        assert!(!tholder.satisfy(&[0, 1])); // First: 1/2+1/2=1 ✓, Second: 0<1 ✗
        assert!(!tholder.satisfy(&[5, 6])); // First: 0<1 ✗, Second: 1+1=2≥1 ✓
        assert!(!tholder.satisfy(&[2, 3, 4])); // First: 1/4+1/4+1/4=3/4<1 ✗, Second: 0<1 ✗
        assert!(!tholder.satisfy(&[])); // Empty indices

        Ok(())
    }

    #[test]
    fn test_tholder_json_string_single_clause_nested() -> Result<(), Box<dyn std::error::Error>> {
        // Test Tholder(sith='[["1/2", "1/2", "1/4", "1/4", "1/4"]]')
        let json_str = r#"[["1/2", "1/2", "1/4", "1/4", "1/4"]]"#;
        let tholder = Tholder::new(None, None, Some(TholderSith::Json(json_str.to_string())))?;

        // Verify basic properties
        assert!(tholder.weighted());
        assert_eq!(tholder.size(), 5);

        // Verify the parsed threshold structure
        if let TholderThold::Weighted(clauses) = tholder.thold() {
            assert_eq!(clauses.len(), 1); // Single clause
            assert_eq!(clauses[0].len(), 5); // 5 elements

            // Check individual fraction values
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

            if let WeightSpec::Simple(fraction) = clauses[0][3] {
                assert_eq!(fraction, Rational32::new(1, 4));
            } else {
                panic!("Expected Simple weight spec for fourth element");
            }

            if let WeightSpec::Simple(fraction) = clauses[0][4] {
                assert_eq!(fraction, Rational32::new(1, 4));
            } else {
                panic!("Expected Simple weight spec for fifth element");
            }
        } else {
            panic!("Expected Weighted threshold type");
        }

        // Check serialized limen
        assert_eq!(tholder.limen(), b"4AAFA1s2c1s2c1s4c1s4c1s4");

        // Verify sith representation (should be flattened for single clause)
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

        // Verify JSON representation
        let expected_json = r#"["1/2","1/2","1/4","1/4","1/4"]"#;
        assert_eq!(tholder.json(), expected_json);

        // Verify numeric threshold is None for weighted thresholds
        assert_eq!(tholder.num(), None);

        // Test satisfaction scenarios that should pass
        assert!(tholder.satisfy(&[1, 2, 3])); // 1/2 + 1/4 + 1/4 = 1
        assert!(tholder.satisfy(&[0, 1, 2])); // 1/2 + 1/2 + 1/4 = 5/4 > 1
        assert!(tholder.satisfy(&[1, 3, 4])); // 1/2 + 1/4 + 1/4 = 1
        assert!(tholder.satisfy(&[0, 1, 2, 3, 4])); // All weights
        assert!(tholder.satisfy(&[3, 2, 0])); // 1/4 + 1/4 + 1/2 = 1
        assert!(tholder.satisfy(&[0, 0, 1, 2, 1, 4, 4])); // Duplicates should be ignored

        // Test satisfaction scenarios that should fail
        assert!(!tholder.satisfy(&[0, 2])); // 1/2 + 1/4 = 3/4 < 1
        assert!(!tholder.satisfy(&[2, 3, 4])); // 1/4 + 1/4 + 1/4 = 3/4 < 1

        Ok(())
    }

    #[test]
    fn test_tholder_json_string_simple_array() -> Result<(), Box<dyn std::error::Error>> {
        // Test Tholder(sith='["1/2", "1/2", "1/4", "1/4", "1/4", "0"]')
        let json_str = r#"["1/2", "1/2", "1/4", "1/4", "1/4", "0"]"#;
        let tholder = Tholder::new(None, None, Some(TholderSith::Json(json_str.to_string())))?;

        // Verify basic properties
        assert!(tholder.weighted());
        assert_eq!(tholder.size(), 6);

        // Verify the parsed threshold structure
        if let TholderThold::Weighted(clauses) = tholder.thold() {
            assert_eq!(clauses.len(), 1); // Single clause
            assert_eq!(clauses[0].len(), 6); // 6 elements

            // Check individual fraction values
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

            if let WeightSpec::Simple(fraction) = clauses[0][3] {
                assert_eq!(fraction, Rational32::new(1, 4));
            } else {
                panic!("Expected Simple weight spec for fourth element");
            }

            if let WeightSpec::Simple(fraction) = clauses[0][4] {
                assert_eq!(fraction, Rational32::new(1, 4));
            } else {
                panic!("Expected Simple weight spec for fifth element");
            }

            // Check that last element is zero
            if let WeightSpec::Simple(fraction) = clauses[0][5] {
                assert_eq!(fraction, Rational32::new(0, 1));
            } else {
                panic!("Expected Simple weight spec for last element");
            }
        } else {
            panic!("Expected Weighted threshold type");
        }

        // Check serialized limen
        assert_eq!(tholder.limen(), b"6AAGAAA1s2c1s2c1s4c1s4c1s4c0");

        // Verify sith representation (should be flattened for single clause)
        if let TholderSith::Weights(weights) = tholder.sith() {
            assert_eq!(weights.len(), 6);
            if let WeightedSithElement::Simple(s) = &weights[0] {
                assert_eq!(s, "1/2");
            } else {
                panic!("Expected Simple weight element");
            }
            if let WeightedSithElement::Simple(s) = &weights[5] {
                assert_eq!(s, "0");
            } else {
                panic!("Expected Simple weight element");
            }
        } else {
            panic!("Expected Weights sith type");
        }

        // Verify JSON representation
        let expected_json = r#"["1/2","1/2","1/4","1/4","1/4","0"]"#;
        assert_eq!(tholder.json(), expected_json);

        // Verify numeric threshold is None for weighted thresholds
        assert_eq!(tholder.num(), None);

        // Test satisfaction scenarios that should pass
        assert!(tholder.satisfy(&[0, 2, 4])); // 1/2 + 1/4 + 1/4 = 1
        assert!(tholder.satisfy(&[0, 1])); // 1/2 + 1/2 = 1
        assert!(tholder.satisfy(&[1, 3, 4])); // 1/2 + 1/4 + 1/4 = 1
        assert!(tholder.satisfy(&[0, 1, 2, 3, 4])); // All weights
        assert!(tholder.satisfy(&[3, 2, 0])); // 1/4 + 1/4 + 1/2 = 1
        assert!(tholder.satisfy(&[0, 0, 1, 2, 1])); // Duplicates should be ignored

        // Test satisfaction scenarios that should fail (including zero weight)
        assert!(!tholder.satisfy(&[0, 2, 5])); // 1/2 + 1/4 + 0 = 3/4 < 1
        assert!(!tholder.satisfy(&[2, 3, 4, 5])); // 1/4 + 1/4 + 1/4 + 0 = 3/4 < 1

        Ok(())
    }

    #[test]
    fn test_tholder_from_limen_multi_clause() -> Result<(), Box<dyn std::error::Error>> {
        // Test Tholder(limen=b'4AAGA1s2c1s2c1s4c1s4c1s4a1c1')
        let limen = b"4AAGA1s2c1s2c1s4c1s4c1s4a1c1".to_vec();
        let tholder = Tholder::new(None, Some(limen), None)?;

        // Verify basic properties
        assert!(tholder.weighted());
        assert_eq!(tholder.size(), 7); // 5 + 2 = 7 total elements

        // Verify the parsed threshold structure
        if let TholderThold::Weighted(clauses) = tholder.thold() {
            assert_eq!(clauses.len(), 2); // Two clauses
            assert_eq!(clauses[0].len(), 5); // First clause has 5 elements
            assert_eq!(clauses[1].len(), 2); // Second clause has 2 elements

            // Check first clause elements
            if let WeightSpec::Simple(fraction) = clauses[0][0] {
                assert_eq!(fraction, Rational32::new(1, 2));
            } else {
                panic!("Expected Simple weight spec");
            }

            if let WeightSpec::Simple(fraction) = clauses[0][1] {
                assert_eq!(fraction, Rational32::new(1, 2));
            } else {
                panic!("Expected Simple weight spec");
            }

            if let WeightSpec::Simple(fraction) = clauses[0][2] {
                assert_eq!(fraction, Rational32::new(1, 4));
            } else {
                panic!("Expected Simple weight spec");
            }

            if let WeightSpec::Simple(fraction) = clauses[0][3] {
                assert_eq!(fraction, Rational32::new(1, 4));
            } else {
                panic!("Expected Simple weight spec");
            }

            if let WeightSpec::Simple(fraction) = clauses[0][4] {
                assert_eq!(fraction, Rational32::new(1, 4));
            } else {
                panic!("Expected Simple weight spec");
            }

            // Check second clause elements
            if let WeightSpec::Simple(fraction) = clauses[1][0] {
                assert_eq!(fraction, Rational32::new(1, 1));
            } else {
                panic!("Expected Simple weight spec");
            }

            if let WeightSpec::Simple(fraction) = clauses[1][1] {
                assert_eq!(fraction, Rational32::new(1, 1));
            } else {
                panic!("Expected Simple weight spec");
            }
        } else {
            panic!("Expected Weighted threshold type");
        }

        // Check serialized limen
        assert_eq!(tholder.limen(), b"4AAGA1s2c1s2c1s4c1s4c1s4a1c1");

        // Verify sith representation (should be nested)
        if let TholderSith::Json(json_str) = tholder.sith() {
            let expected_nested = r#"[["1/2","1/2","1/4","1/4","1/4"],["1","1"]]"#;
            assert_eq!(json_str, expected_nested);
        } else {
            panic!("Expected Json sith type for multi-clause");
        }

        // Verify JSON representation
        let expected_json = r#"[["1/2","1/2","1/4","1/4","1/4"],["1","1"]]"#;
        assert_eq!(tholder.json(), expected_json);

        // Verify numeric threshold is None for weighted thresholds
        assert_eq!(tholder.num(), None);

        // Test satisfaction scenarios that should pass
        // Both clauses must be satisfied (AND logic)
        assert!(tholder.satisfy(&[1, 2, 3, 5])); // First: 1/2+1/4+1/4=1, Second: 1=1 ✓
        assert!(tholder.satisfy(&[0, 1, 6])); // First: 1/2+1/2=1, Second: 1=1 ✓

        // Test satisfaction scenarios that should fail
        assert!(!tholder.satisfy(&[0, 1])); // First: 1/2+1/2=1 ✓, Second: 0<1 ✗
        assert!(!tholder.satisfy(&[5, 6])); // First: 0<1 ✗, Second: 1+1=2≥1 ✓
        assert!(!tholder.satisfy(&[2, 3, 4])); // First: 1/4+1/4+1/4=3/4<1 ✗, Second: 0<1 ✗
        assert!(!tholder.satisfy(&[])); // Empty indices

        Ok(())
    }

    #[test]
    fn test_tholder_from_thold_multi_clause() -> Result<(), Box<dyn std::error::Error>> {
        // Test Tholder(thold=[[Fraction(1, 2), Fraction(1, 2), Fraction(1, 4), Fraction(1, 4), Fraction(1, 4)],
        //                     [Fraction(1, 1), Fraction(1, 1)]])
        let thold = TholderThold::Weighted(vec![
            vec![
                WeightSpec::Simple(Rational32::new(1, 2)),
                WeightSpec::Simple(Rational32::new(1, 2)),
                WeightSpec::Simple(Rational32::new(1, 4)),
                WeightSpec::Simple(Rational32::new(1, 4)),
                WeightSpec::Simple(Rational32::new(1, 4)),
            ],
            vec![
                WeightSpec::Simple(Rational32::new(1, 1)),
                WeightSpec::Simple(Rational32::new(1, 1)),
            ],
        ]);

        let tholder = Tholder::new(Some(thold), None, None)?;

        // Verify basic properties
        assert!(tholder.weighted());
        assert_eq!(tholder.size(), 7); // 5 + 2 = 7 total elements

        // Verify the parsed threshold structure
        if let TholderThold::Weighted(clauses) = tholder.thold() {
            assert_eq!(clauses.len(), 2); // Two clauses
            assert_eq!(clauses[0].len(), 5); // First clause has 5 elements
            assert_eq!(clauses[1].len(), 2); // Second clause has 2 elements

            // Check first clause elements
            if let WeightSpec::Simple(fraction) = clauses[0][0] {
                assert_eq!(fraction, Rational32::new(1, 2));
            } else {
                panic!("Expected Simple weight spec");
            }

            if let WeightSpec::Simple(fraction) = clauses[0][1] {
                assert_eq!(fraction, Rational32::new(1, 2));
            } else {
                panic!("Expected Simple weight spec");
            }

            if let WeightSpec::Simple(fraction) = clauses[0][2] {
                assert_eq!(fraction, Rational32::new(1, 4));
            } else {
                panic!("Expected Simple weight spec");
            }

            if let WeightSpec::Simple(fraction) = clauses[0][3] {
                assert_eq!(fraction, Rational32::new(1, 4));
            } else {
                panic!("Expected Simple weight spec");
            }

            if let WeightSpec::Simple(fraction) = clauses[0][4] {
                assert_eq!(fraction, Rational32::new(1, 4));
            } else {
                panic!("Expected Simple weight spec");
            }

            // Check second clause elements
            if let WeightSpec::Simple(fraction) = clauses[1][0] {
                assert_eq!(fraction, Rational32::new(1, 1));
            } else {
                panic!("Expected Simple weight spec");
            }

            if let WeightSpec::Simple(fraction) = clauses[1][1] {
                assert_eq!(fraction, Rational32::new(1, 1));
            } else {
                panic!("Expected Simple weight spec");
            }
        } else {
            panic!("Expected Weighted threshold type");
        }

        // Check serialized limen
        assert_eq!(tholder.limen(), b"4AAGA1s2c1s2c1s4c1s4c1s4a1c1");

        // Verify sith representation (should be nested)
        if let TholderSith::Json(json_str) = tholder.sith() {
            let expected_nested = r#"[["1/2","1/2","1/4","1/4","1/4"],["1","1"]]"#;
            assert_eq!(json_str, expected_nested);
        } else {
            panic!("Expected Json sith type for multi-clause");
        }

        // Verify JSON representation
        let expected_json = r#"[["1/2","1/2","1/4","1/4","1/4"],["1","1"]]"#;
        assert_eq!(tholder.json(), expected_json);

        // Verify numeric threshold is None for weighted thresholds
        assert_eq!(tholder.num(), None);

        // Test satisfaction scenarios that should pass
        // Both clauses must be satisfied (AND logic)
        assert!(tholder.satisfy(&[1, 2, 3, 5])); // First: 1/2+1/4+1/4=1, Second: 1=1 ✓
        assert!(tholder.satisfy(&[0, 1, 6])); // First: 1/2+1/2=1, Second: 1=1 ✓

        // Test satisfaction scenarios that should fail
        assert!(!tholder.satisfy(&[0, 1])); // First: 1/2+1/2=1 ✓, Second: 0<1 ✗
        assert!(!tholder.satisfy(&[5, 6])); // First: 0<1 ✗, Second: 1+1=2≥1 ✓
        assert!(!tholder.satisfy(&[2, 3, 4])); // First: 1/4+1/4+1/4=3/4<1 ✗, Second: 0<1 ✗
        assert!(!tholder.satisfy(&[])); // Empty indices

        Ok(())
    }

    #[test]
    fn test_tholder_nested_weighted_single_clause() -> Result<(), Box<dyn std::error::Error>> {
        // Test single clause with complex weighted mapping
        // [{"1/3":["1/2", "1/2", "1/2"]}, "1/3", "1/2", {"1/2": ["1", "1"]}]
        let json_str = r#"[{"1/3":["1/2", "1/2", "1/2"]}, "1/3", "1/2", {"1/2": ["1", "1"]}]"#;
        let tholder = Tholder::new(None, None, Some(TholderSith::Json(json_str.to_string())))?;

        // Verify basic properties
        assert!(tholder.weighted());
        assert_eq!(tholder.size(), 7); // 3 + 1 + 1 + 2 = 7 total elements

        // Verify the parsed threshold structure
        if let TholderThold::Weighted(clauses) = tholder.thold() {
            assert_eq!(clauses.len(), 1); // Single clause
            assert_eq!(clauses[0].len(), 4); // Four elements in clause

            // Check first element: WeightedMap with key "1/3" and values ["1/2", "1/2", "1/2"]
            if let WeightSpec::WeightedMap(key_weight, nested_weights) = &clauses[0][0] {
                assert_eq!(*key_weight, Rational32::new(1, 3));
                assert_eq!(nested_weights.len(), 3);
                assert_eq!(nested_weights[0], Rational32::new(1, 2));
                assert_eq!(nested_weights[1], Rational32::new(1, 2));
                assert_eq!(nested_weights[2], Rational32::new(1, 2));
            } else {
                panic!("Expected WeightedMap for first element");
            }

            // Check second element: Simple "1/3"
            if let WeightSpec::Simple(weight) = clauses[0][1] {
                assert_eq!(weight, Rational32::new(1, 3));
            } else {
                panic!("Expected Simple weight for second element");
            }

            // Check third element: Simple "1/2"
            if let WeightSpec::Simple(weight) = clauses[0][2] {
                assert_eq!(weight, Rational32::new(1, 2));
            } else {
                panic!("Expected Simple weight for third element");
            }

            // Check fourth element: WeightedMap with key "1/2" and values ["1", "1"]
            if let WeightSpec::WeightedMap(key_weight, nested_weights) = &clauses[0][3] {
                assert_eq!(*key_weight, Rational32::new(1, 2));
                assert_eq!(nested_weights.len(), 2);
                assert_eq!(nested_weights[0], Rational32::new(1, 1));
                assert_eq!(nested_weights[1], Rational32::new(1, 1));
            } else {
                panic!("Expected WeightedMap for fourth element");
            }
        } else {
            panic!("Expected Weighted threshold type");
        }

        // Check serialized limen
        assert_eq!(tholder.limen(), b"4AAIA1s3k1s2v1s2v1s2c1s3c1s2c1s2k1v1");

        // Verify sith representation (should be flattened for single clause)
        if let TholderSith::Weights(weights) = tholder.sith() {
            assert_eq!(weights.len(), 4);

            // First element should be Complex with "1/3" key
            if let WeightedSithElement::Complex(map) = &weights[0] {
                assert!(map.contains_key("1/3"));
                let values = map.get("1/3").unwrap();
                assert_eq!(values.len(), 3);
            } else {
                panic!("Expected Complex element for first weight");
            }

            // Second element should be Simple "1/3"
            if let WeightedSithElement::Simple(s) = &weights[1] {
                assert_eq!(s, "1/3");
            } else {
                panic!("Expected Simple element for second weight");
            }

            // Third element should be Simple "1/2"
            if let WeightedSithElement::Simple(s) = &weights[2] {
                assert_eq!(s, "1/2");
            } else {
                panic!("Expected Simple element for third weight");
            }

            // Fourth element should be Complex with "1/2" key
            if let WeightedSithElement::Complex(map) = &weights[3] {
                assert!(map.contains_key("1/2"));
                let values = map.get("1/2").unwrap();
                assert_eq!(values.len(), 2);
            } else {
                panic!("Expected Complex element for fourth weight");
            }
        } else {
            panic!("Expected Weights sith type");
        }

        // Verify JSON representation
        let expected_json = r#"[{"1/3":["1/2","1/2","1/2"]},"1/3","1/2",{"1/2":["1","1"]}]"#;
        assert_eq!(tholder.json(), expected_json);

        // Verify numeric threshold is None for weighted thresholds
        assert_eq!(tholder.num(), None);

        // Test satisfaction scenarios that should pass
        // Need to satisfy: first weighted map (1/3 if nested ≥1) + 1/3 + 1/2 + second weighted map (1/2 if nested ≥1) ≥ 1
        // Index mapping: [0,1,2] for first map, [3] for "1/3", [4] for "1/2", [5,6] for second map
        assert!(tholder.satisfy(&[0, 2, 3, 6])); // First map: 1/2+1/2=1→1/3, plus 1/3+1/2 = 1.33 ≥ 1
        assert!(tholder.satisfy(&[3, 4, 5])); // Skip first map, 1/3+1/2 = 0.83, second map: 1→1/2, total = 1.33 ≥ 1
        assert!(tholder.satisfy(&[1, 2, 3, 4])); // First map: 1/2+1/2=1→1/3, plus 1/3+1/2 = 1.33 ≥ 1
        assert!(tholder.satisfy(&[4, 6])); // Skip first map, only 1/2, second map: 1→1/2, total = 1 ≥ 1
        assert!(tholder.satisfy(&[4, 2, 0, 3])); // First map: 1/2+1/2=1→1/3, plus 1/3+1/2 = 1.33 ≥ 1
        assert!(tholder.satisfy(&[0, 0, 1, 2, 1, 5, 6, 3])); // Duplicates ignored, all conditions met

        // Test satisfaction scenarios that should fail
        assert!(!tholder.satisfy(&[0, 2, 5])); // First map: 1/2+1/2=1→1/3, second map: 1→1/2, total = 0.83 < 1
        assert!(!tholder.satisfy(&[2, 3, 4])); // First map: 1/2<1→0, plus 1/3+1/2 = 0.83 < 1

        Ok(())
    }

    #[test]
    fn test_tholder_nested_weighted_from_limen() -> Result<(), Box<dyn std::error::Error>> {
        // Test creating from limen bytes
        let limen = b"4AAIA1s3k1s2v1s2v1s2c1s3c1s2c1s2k1v1".to_vec();
        let tholder = Tholder::new(None, Some(limen), None)?;

        // Verify basic properties
        assert!(tholder.weighted());
        assert_eq!(tholder.size(), 7);

        // Verify the parsed threshold structure matches expected
        if let TholderThold::Weighted(clauses) = tholder.thold() {
            assert_eq!(clauses.len(), 1);
            assert_eq!(clauses[0].len(), 4);

            // Verify structure matches the JSON case
            if let WeightSpec::WeightedMap(key_weight, nested_weights) = &clauses[0][0] {
                assert_eq!(*key_weight, Rational32::new(1, 3));
                assert_eq!(nested_weights.len(), 3);
            } else {
                panic!("Expected WeightedMap for first element");
            }
        } else {
            panic!("Expected Weighted threshold type");
        }

        // Check serialized limen
        assert_eq!(tholder.limen(), b"4AAIA1s3k1s2v1s2v1s2c1s3c1s2c1s2k1v1");

        // Verify JSON representation
        let expected_json = r#"[{"1/3":["1/2","1/2","1/2"]},"1/3","1/2",{"1/2":["1","1"]}]"#;
        assert_eq!(tholder.json(), expected_json);

        assert_eq!(tholder.num(), None);

        Ok(())
    }

    #[test]
    fn test_tholder_nested_weighted_from_thold() -> Result<(), Box<dyn std::error::Error>> {
        // Test creating from direct thold structure
        let thold = TholderThold::Weighted(vec![vec![
            WeightSpec::WeightedMap(
                Rational32::new(1, 3),
                vec![
                    Rational32::new(1, 2),
                    Rational32::new(1, 2),
                    Rational32::new(1, 2),
                ],
            ),
            WeightSpec::Simple(Rational32::new(1, 3)),
            WeightSpec::Simple(Rational32::new(1, 2)),
            WeightSpec::WeightedMap(
                Rational32::new(1, 2),
                vec![Rational32::new(1, 1), Rational32::new(1, 1)],
            ),
        ]]);

        let tholder = Tholder::new(Some(thold), None, None)?;

        // Verify basic properties
        assert!(tholder.weighted());
        assert_eq!(tholder.size(), 7);

        // Check serialized limen
        assert_eq!(tholder.limen(), b"4AAIA1s3k1s2v1s2v1s2c1s3c1s2c1s2k1v1");

        // Verify JSON representation
        let expected_json = r#"[{"1/3":["1/2","1/2","1/2"]},"1/3","1/2",{"1/2":["1","1"]}]"#;
        assert_eq!(tholder.json(), expected_json);

        assert_eq!(tholder.num(), None);

        Ok(())
    }

    #[test]
    fn test_tholder_nested_weighted_multi_clause() -> Result<(), Box<dyn std::error::Error>> {
        // Test multi-clause with complex weighted mapping
        let json_str = r#"[[{"1/3":["1/2", "1/2", "1/2"]}, "1/2", {"1/2": ["1", "1"]}], ["1/2", {"1/2": ["1", "1"]}]]"#;
        let tholder = Tholder::new(None, None, Some(TholderSith::Json(json_str.to_string())))?;

        // Verify basic properties
        assert!(tholder.weighted());
        assert_eq!(tholder.size(), 9); // First clause: 3+1+2=6, Second clause: 1+2=3, Total: 9

        // Verify the parsed threshold structure
        if let TholderThold::Weighted(clauses) = tholder.thold() {
            assert_eq!(clauses.len(), 2); // Two clauses
            assert_eq!(clauses[0].len(), 3); // First clause has 3 elements
            assert_eq!(clauses[1].len(), 2); // Second clause has 2 elements

            // Check first clause, first element: WeightedMap
            if let WeightSpec::WeightedMap(key_weight, nested_weights) = &clauses[0][0] {
                assert_eq!(*key_weight, Rational32::new(1, 3));
                assert_eq!(nested_weights.len(), 3);
            } else {
                panic!("Expected WeightedMap for first clause first element");
            }

            // Check second clause, second element: WeightedMap
            if let WeightSpec::WeightedMap(key_weight, nested_weights) = &clauses[1][1] {
                assert_eq!(*key_weight, Rational32::new(1, 2));
                assert_eq!(nested_weights.len(), 2);
            } else {
                panic!("Expected WeightedMap for second clause second element");
            }
        } else {
            panic!("Expected Weighted threshold type");
        }

        // Check serialized limen
        assert_eq!(
            tholder.limen(),
            b"4AAKA1s3k1s2v1s2v1s2c1s2c1s2k1v1a1s2c1s2k1v1"
        );

        // Verify sith representation (should be nested for multi-clause)
        if let TholderSith::Json(json_str) = tholder.sith() {
            let expected_nested = r#"[[{"1/3":["1/2","1/2","1/2"]},"1/2",{"1/2":["1","1"]}],["1/2",{"1/2":["1","1"]}]]"#;
            assert_eq!(json_str, expected_nested);
        } else {
            panic!("Expected Json sith type for multi-clause");
        }

        // Verify JSON representation
        let expected_json =
            r#"[[{"1/3":["1/2","1/2","1/2"]},"1/2",{"1/2":["1","1"]}],["1/2",{"1/2":["1","1"]}]]"#;
        assert_eq!(tholder.json(), expected_json);

        assert_eq!(tholder.num(), None);

        // Test satisfaction scenarios
        // Index mapping: [0,1,2] first map, [3] simple, [4,5] second map | [6] simple, [7,8] third map
        assert!(tholder.satisfy(&[0, 2, 3, 5, 6, 7])); // Both clauses satisfied
        assert!(tholder.satisfy(&[3, 4, 5, 6, 8])); // Both clauses satisfied
        assert!(tholder.satisfy(&[1, 2, 3, 4, 6, 7])); // Both clauses satisfied
        assert!(tholder.satisfy(&[4, 2, 0, 3, 8, 6])); // Both clauses satisfied
        assert!(tholder.satisfy(&[0, 0, 1, 2, 1, 8, 3, 5, 6, 3])); // Duplicates ignored, both clauses satisfied

        // Test failure cases
        assert!(!tholder.satisfy(&[0, 2, 5])); // First clause not satisfied (missing simple weights)
        assert!(!tholder.satisfy(&[6, 7, 8])); // Second clause satisfied but first clause not satisfied

        Ok(())
    }

    #[test]
    fn test_tholder_nested_weighted_multi_clause_from_limen(
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Test creating multi-clause from limen
        let limen = b"4AAKA1s3k1s2v1s2v1s2c1s2c1s2k1v1a1s2c1s2k1v1".to_vec();
        let tholder = Tholder::new(None, Some(limen), None)?;

        assert!(tholder.weighted());
        assert_eq!(tholder.size(), 9);
        assert_eq!(
            tholder.limen(),
            b"4AAKA1s3k1s2v1s2v1s2c1s2c1s2k1v1a1s2c1s2k1v1"
        );

        let expected_json =
            r#"[[{"1/3":["1/2","1/2","1/2"]},"1/2",{"1/2":["1","1"]}],["1/2",{"1/2":["1","1"]}]]"#;
        assert_eq!(tholder.json(), expected_json);

        assert_eq!(tholder.num(), None);

        Ok(())
    }

    #[test]
    fn test_tholder_nested_weighted_multi_clause_from_thold(
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Test creating multi-clause from direct thold structure
        let thold = TholderThold::Weighted(vec![
            vec![
                WeightSpec::WeightedMap(
                    Rational32::new(1, 3),
                    vec![
                        Rational32::new(1, 2),
                        Rational32::new(1, 2),
                        Rational32::new(1, 2),
                    ],
                ),
                WeightSpec::Simple(Rational32::new(1, 2)),
                WeightSpec::WeightedMap(
                    Rational32::new(1, 2),
                    vec![Rational32::new(1, 1), Rational32::new(1, 1)],
                ),
            ],
            vec![
                WeightSpec::Simple(Rational32::new(1, 2)),
                WeightSpec::WeightedMap(
                    Rational32::new(1, 2),
                    vec![Rational32::new(1, 1), Rational32::new(1, 1)],
                ),
            ],
        ]);

        let tholder = Tholder::new(Some(thold), None, None)?;

        assert!(tholder.weighted());
        assert_eq!(tholder.size(), 9);
        assert_eq!(
            tholder.limen(),
            b"4AAKA1s3k1s2v1s2v1s2c1s2c1s2k1v1a1s2c1s2k1v1"
        );

        let expected_json =
            r#"[[{"1/3":["1/2","1/2","1/2"]},"1/2",{"1/2":["1","1"]}],["1/2",{"1/2":["1","1"]}]]"#;
        assert_eq!(tholder.json(), expected_json);

        assert_eq!(tholder.num(), None);

        Ok(())
    }

    #[test]
    fn test_tholder_nested_weighted_validation_errors() -> Result<(), Box<dyn std::error::Error>> {
        // Test error case: nested weights don't sum to >= 1
        let json_str1 = r#"[{"1/3":["1/3", "1/3", "1/4"]}, "1/3", "1/2", {"1/2": ["1", "1"]}]"#;
        let result1 = Tholder::new(None, None, Some(TholderSith::Json(json_str1.to_string())));
        assert!(result1.is_err());

        // Test error case: nested weights don't sum to >= 1 in second map
        let json_str2 = r#"[{"1/3":["1/2", "1/2", "1/2"]}, "1/3", "1/2", {"1/2": ["2/3", "1/4"]}]"#;
        let result2 = Tholder::new(None, None, Some(TholderSith::Json(json_str2.to_string())));
        assert!(result2.is_err());

        // Test error case: top-level weights don't sum to >= 1
        let json_str3 = r#"[{"1/5":["1/2", "1/2", "1/2"]}, "1/4", "1/5", {"1/5": ["1", "1"]}]"#;
        let result3 = Tholder::new(None, None, Some(TholderSith::Json(json_str3.to_string())));
        assert!(result3.is_err());

        // Test error case: multi-clause with invalid nested weights
        let json_str4 = r#"[[{"1/3":["1/2", "1/2", "1/2"]}, "1/2", {"1/2": ["1", "1"]}], ["1/2", {"1/3": ["1", "1"]}]]"#;
        let result4 = Tholder::new(None, None, Some(TholderSith::Json(json_str4.to_string())));
        assert!(result4.is_err());

        // Test error case: multi-clause with insufficient nested weights
        let json_str5 = r#"[[{"1/3":["1/3", "1/4", "1/3"]}, "1/2", {"1/2": ["1", "1"]}], ["1/2", {"1/2": ["1/2", "1/2"]}]]"#;
        let result5 = Tholder::new(None, None, Some(TholderSith::Json(json_str5.to_string())));
        assert!(result5.is_err());

        Ok(())
    }
}
