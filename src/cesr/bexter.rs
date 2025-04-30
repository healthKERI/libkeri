use crate::cesr::{bex_dex, decode_b64, encode_b64, get_sizes, BaseMatter, Parsable};
use crate::errors::MatterError;
use crate::Matter;
use std::any::Any;

///  Bexter is subclass of Matter, cryptographic material, for variable length
///  strings that only contain Base64 URL safe characters, i.e. Base64 text (bext).
///  When created using the 'bext' paramaeter, the encoded matter in qb64 format
///  in the text domain is more compact than would be the case if the string were
///  passed in as raw bytes. The text is used as is to form the value part of the
///  qb64 version not including the leader.
///
///  Due to ambiguity that arises from pre-padding bext whose length is a multiple of
///  three with one or more 'A' chars. Any bext that starts with an 'A' and whose length
///  is either a multiple of 3 or 4 may not round trip. Bext with a leading 'A'
///  whose length is a multiple of four may have the leading 'A' stripped when
///  round tripping.

#[derive(Debug, Clone)]
pub struct Bexter {
    base: BaseMatter,
}

impl Bexter {
    /// Creates a new Number from a numeric value
    pub fn new(
        raw: Option<&[u8]>,
        code: Option<&str>,
        soft: Option<&str>,
        rize: Option<usize>,
    ) -> Result<Self, MatterError> {
        if !bex_dex::TUPLE.contains(&(code.unwrap())) {
            return Err(MatterError::UnsupportedCodeError(String::from(
                code.unwrap_or("None"),
            )));
        }

        let base = BaseMatter::new(raw, code, soft, rize)?;
        Ok(Bexter { base })
    }

    pub fn from_qb64(qb64: &str) -> Result<Self, MatterError> {
        let base = BaseMatter::from_qb64(qb64)?;
        if !bex_dex::TUPLE.contains(&(base.code())) {
            return Err(MatterError::UnsupportedCodeError(String::from(base.code())));
        }

        Ok(Bexter { base })
    }

    pub fn bext(&self) -> Result<String, MatterError> {
        Self::derawify(self.raw(), self.code())
    }

    /// Converts Base64 URL-safe text to its raw binary equivalent
    ///
    /// This is a direct port of the Python `_rawify` method.
    ///
    /// # Arguments
    ///
    /// * `bext` - Base64 URL-safe bytes
    ///
    /// # Returns
    ///
    /// * `Result<Vec<u8>, MatterError>` - Raw binary equivalent of the input text
    pub fn rawify(bext: &[u8]) -> Result<Vec<u8>, MatterError> {
        // Calculate padding and lead sizes
        let ts = bext.len() % 4; // bext size mod 4
        let ws = (4 - ts) % 4; // pre-conversion padding size in chars
        let ls = (3 - ts) % 3; // post-conversion lead size in bytes

        // Create a new buffer with padding
        let mut base = Vec::with_capacity(ws + bext.len());

        // Add padding with 'A's (equivalent to zero in Base64)
        base.extend(vec![b'A'; ws]);

        // Add the original bext data
        base.extend_from_slice(bext);

        // Convert to string for base64 decoding (assuming URL-safe base64)
        let base_str = std::str::from_utf8(&base)
            .map_err(|_| MatterError::DecodingError("Invalid UTF-8 in base64 input".to_string()))?;

        // Decode the base64 string
        let decoded = decode_b64(base_str)?;

        // Return the decoded bytes without the leading bytes
        if ls < decoded.len() {
            Ok(decoded[ls..].to_vec())
        } else {
            // Handle edge case where ls >= decoded.len()
            Ok(Vec::new())
        }
    }

    /// Creates a new Bexter instance from a Base64 encoded text
    pub fn from_bext(bext: &[u8]) -> Result<Self, MatterError> {
        let raw = Self::rawify(bext)?;
        Self::new(Some(&raw), Some(bex_dex::TUPLE[0]), None, None)
    }

    /// Converts raw binary data back to Base64 URL-safe text (bext)
    ///
    /// This is a direct port of the Python `_derawify` method.
    ///
    /// # Arguments
    ///
    /// * `raw` - Raw binary data
    /// * `code` - Code identifying the encoding format
    ///
    /// # Returns
    ///
    /// * `Result<String, MatterError>` - Base64 URL-safe text equivalent
    pub fn derawify(raw: &[u8], code: &str) -> Result<String, MatterError> {
        // Get the lead size (ls) for the given code
        let sizes = get_sizes();
        let ls = match sizes.get(code) {
            Some(size) => size.ls,
            None => return Err(MatterError::UnsupportedCodeError(code.to_string())),
        };

        // Create lead bytes (zeros)
        let lead_bytes = vec![0u8; ls as usize];

        // Concatenate lead bytes with raw data
        let mut full_data = Vec::with_capacity(lead_bytes.len() + raw.len());
        full_data.extend_from_slice(&lead_bytes);
        full_data.extend_from_slice(raw);

        // Encode to Base64
        let bext = encode_b64(&full_data);

        // Calculate padding to remove
        let ws = if ls == 0 && !bext.is_empty() {
            // Check if we need to strip leading 'A' (zero pad)
            if bext.starts_with('A') {
                1
            } else {
                0
            }
        } else {
            (ls + 1) % 4
        };

        // Return the bext with leading padding removed
        if ws < bext.len() as u32 {
            Ok(bext[ws as usize..].to_string())
        } else {
            // Handle edge case where ws >= bext.len()
            Ok(String::new())
        }
    }
}

impl Parsable for Bexter {
    fn from_qb64b(data: &mut Vec<u8>, strip: Option<bool>) -> Result<Self, MatterError> {
        let base = BaseMatter::from_qb64b(data, strip)?;
        if !bex_dex::TUPLE.contains(&(base.code())) {
            return Err(MatterError::UnsupportedCodeError(String::from(base.code())));
        }

        Ok(Bexter { base })
    }

    fn from_qb2(data: &mut Vec<u8>, strip: Option<bool>) -> Result<Self, MatterError> {
        let base = BaseMatter::from_qb2(data, strip)?;
        if !bex_dex::TUPLE.contains(&(base.code())) {
            return Err(MatterError::UnsupportedCodeError(String::from(base.code())));
        }

        Ok(Bexter { base })
    }
}

impl Matter for Bexter {
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
