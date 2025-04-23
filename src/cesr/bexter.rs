use crate::cesr::{bex_dex, BaseMatter, Parsable};
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

    pub fn bext(&self) -> String {
        "".to_string()
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
