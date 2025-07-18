use crate::cesr::{get_sizes, mtr_dex, BaseMatter, Parsable};
use crate::errors::MatterError;
use crate::Matter;
use lazy_static::lazy_static;
use std::any::Any;
use std::collections::HashMap;

// Static instance that can be used throughout the application
lazy_static! {
    pub static ref B64_TRANSLATOR: B64Translator = B64Translator::new();
}

/// Dater represents RFC-3339 formatted datetimes
#[derive(Debug, Clone)]
pub struct Dater {
    base: BaseMatter,
}

#[allow(dead_code)]
impl Dater {
    pub fn from_dt(dt: chrono::DateTime<chrono::Utc>) -> Self {
        let dts = dt.to_rfc3339();
        let raw = dts.as_bytes().to_vec();
        let base = BaseMatter::new(Some(&raw), Some(mtr_dex::DATE_TIME), None, None).unwrap();
        Dater { base }
    }

    pub fn from_dts(dts: &str) -> Result<Self, MatterError> {
        let raw = dts.as_bytes();
        let base = BaseMatter::new(Some(raw), Some(mtr_dex::DATE_TIME), None, None)?;
        Ok(Dater { base })
    }

    pub fn new(
        raw: Option<&[u8]>,
        code: Option<&str>,
        soft: Option<&str>,
        rize: Option<usize>,
    ) -> Result<Self, MatterError> {
        if code.unwrap() != mtr_dex::DATE_TIME {
            return Err(MatterError::UnsupportedCodeError(String::from(
                code.unwrap_or("None"),
            )));
        }

        let base = BaseMatter::new(raw, code, soft, rize)?;
        Ok(Dater { base })
    }

    pub fn from_raw(raw: Option<&[u8]>) -> Result<Self, MatterError> {
        let base = BaseMatter::new(raw, Some(mtr_dex::DATE_TIME), None, None)?;

        Ok(Dater { base })
    }

    pub fn from_qb64(qb64: &str) -> Result<Self, MatterError> {
        let base = BaseMatter::from_qb64(qb64)?;
        if base.code() != mtr_dex::DATE_TIME {
            return Err(MatterError::UnsupportedCodeError(String::from(base.code())));
        }

        Ok(Dater { base })
    }

    /// Returns the datetime string
    pub fn dts(&self) -> String {
        let qb64 = self.base.qb64();
        let sizes = get_sizes();
        let size = sizes.get(mtr_dex::DATE_TIME).unwrap();
        B64_TRANSLATOR.from_b64(&qb64[size.hs as usize..])
    }

    pub fn dtsb(&self) -> Vec<u8> {
        let dts = self.dts();
        dts.as_bytes().to_vec()
    }

    /// Returns the datetime as a DateTime<Utc> object
    pub fn dt(&self) -> Result<chrono::DateTime<chrono::Utc>, MatterError> {
        let dts = self.dts();
        chrono::DateTime::parse_from_rfc3339(&dts)
            .map(|dt| dt.with_timezone(&chrono::Utc))
            .map_err(|_| MatterError::InvalidFormat)
    }
}

impl Parsable for Dater {
    fn from_qb64b(data: &mut Vec<u8>, strip: Option<bool>) -> Result<Self, MatterError> {
        let base = BaseMatter::from_qb64b(data, strip)?;
        if base.code() != mtr_dex::DATE_TIME {
            return Err(MatterError::UnsupportedCodeError(String::from(base.code())));
        }

        Ok(Dater { base })
    }

    fn from_qb2(data: &mut Vec<u8>, strip: Option<bool>) -> Result<Self, MatterError> {
        let base = BaseMatter::from_qb2(data, strip)?;
        if base.code() != mtr_dex::DATE_TIME {
            return Err(MatterError::UnsupportedCodeError(String::from(base.code())));
        }

        Ok(Dater { base })
    }
}

impl Matter for Dater {
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

/// Translator for converting special characters to Base64-friendly versions and back
pub struct B64Translator {
    to_b64_map: HashMap<char, Option<String>>,
    from_b64_map: HashMap<char, Option<String>>,
}

impl B64Translator {
    /// Create a new translator instance with the specified character mappings
    pub fn new() -> Self {
        let mut to_b64_map = HashMap::new();
        to_b64_map.insert(':', Some("c".to_string()));
        to_b64_map.insert('.', Some("d".to_string()));
        to_b64_map.insert('+', Some("p".to_string()));

        let mut from_b64_map = HashMap::new();
        from_b64_map.insert('c', Some(":".to_string()));
        from_b64_map.insert('d', Some(".".to_string()));
        from_b64_map.insert('p', Some("+".to_string()));

        B64Translator {
            to_b64_map,
            from_b64_map,
        }
    }

    /// Translate a string to a Base64-friendly format
    pub fn to_b64(&self, s: &str) -> String {
        self.translate(s, &self.to_b64_map)
    }

    /// Translate a string from a Base64-friendly format back to original
    pub fn from_b64(&self, s: &str) -> String {
        self.translate(s, &self.from_b64_map)
    }

    /// Core translation function that applies the character mappings
    fn translate(&self, s: &str, char_map: &HashMap<char, Option<String>>) -> String {
        let mut result = String::new();

        for c in s.chars() {
            match char_map.get(&c) {
                Some(Some(replacement)) => result.push_str(replacement),
                Some(None) => (),       // Character should be removed
                None => result.push(c), // No mapping, keep original
            }
        }

        result
    }
}
