use std::any::Any;
use crate::cesr::{dig_dex, BaseMatter, Parsable};
use crate::errors::MatterError;
use crate::Matter;

///  Saider is Matter subclass for self-addressing identifier prefix using
///  derivation as determined by code from ked
#[derive(Debug, Clone)]
pub struct Saider {
    base: BaseMatter,
}

impl Saider {

}

impl Matter for Saider {
    fn code(&self) -> &str { self.base.code() }
    fn raw(&self) -> &[u8] { self.base.raw() }
    fn qb64(&self) -> String { self.base.qb64() }
    fn qb64b(&self) -> Vec<u8> { self.base.qb64b() }
    fn qb2(&self) -> Vec<u8> { self.base.qb2() }
    fn soft(&self) -> &str { self.base.soft() }
    fn full_size(&self) -> usize { self.base.full_size() }
    fn size(&self) -> usize { self.base.size() }
    fn is_transferable(&self) -> bool { self.base.is_transferable() }
    fn is_digestive(&self) -> bool { self.base.is_digestive() }
    fn is_prefixive(&self) -> bool { self.base.is_prefixive() }
    fn is_special(&self) -> bool { self.base.is_special() }
    fn as_any(&self) -> &dyn Any { self }
}

impl Parsable for Saider {
    fn from_qb64b(data: &mut Vec<u8>, strip: Option<bool>) -> Result<Self, MatterError> {
        let base = BaseMatter::from_qb64b(data, strip)?;
        if !dig_dex::TUPLE.contains(&(base.code())) {
            return Err(MatterError::UnsupportedCodeError(String::from(base.code())));
        }

        Ok(Saider {
            base,
        })
    }


    fn from_qb2(data: &mut Vec<u8>, strip: Option<bool>) -> Result<Self, MatterError> {
        let base = BaseMatter::from_qb2(data, strip)?;
        if !dig_dex::TUPLE.contains(&(base.code())) {
            return Err(MatterError::UnsupportedCodeError(String::from(base.code())));
        }

        Ok(Saider {
            base,
        })
    }

}