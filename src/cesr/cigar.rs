use std::any::Any;
use crate::cesr::{non_trans_dex, BaseMatter, Parsable};
use crate::cesr::verfer::Verfer;
use crate::errors::MatterError;
use crate::Matter;

///  Cigar is Matter subclass holding a nonindexed signature with verfer property.
///  From Matter .raw is signature and .code is signature cipher suite
///  Adds .verfer property to hold Verfer instance of associated verifier public key
///  Verfer's .raw as verifier key and .code is verifier cipher suite.

#[derive(Debug, Clone)]
pub struct Cigar {
    base: BaseMatter,
    pub verfer: Option<Verfer>,
}

impl Cigar {
    pub fn new(raw: Option<&[u8]>, code: Option<&str>, soft: Option<&str>, rize: Option<usize>, verfer: Option<Verfer>) -> Result<Self, MatterError> {
        let base = BaseMatter::new(raw, code, soft, rize)?;
        Ok(Cigar {
            base,
            verfer,
        })
    }

    pub fn from_raw(raw: Option<&[u8]>, verfer: Option<Verfer>) -> Result<Self, MatterError> {
        let base = BaseMatter::from_raw(raw)?;

        Ok(Cigar {
            base,
            verfer
        })
    }

    pub fn from_qb64(qb64: &str, verfer: Option<Verfer>) -> Result<Self, MatterError> {
        let base = BaseMatter::from_qb64(qb64)?;
        if !non_trans_dex::TUPLE.contains(&(base.code())) {
            return Err(MatterError::UnsupportedCodeError(String::from(base.code())));
        }

        Ok(Cigar {
            base,
            verfer
        })
    }

    pub fn verfer(&self) -> &Verfer {
        self.verfer.as_ref().unwrap()
    }
}

impl Parsable for Cigar {
    fn from_qb64b(data: &mut Vec<u8>, strip: Option<bool>) -> Result<Self, MatterError> {
        let base = BaseMatter::from_qb64b(data, strip)?;
        if !non_trans_dex::TUPLE.contains(&(base.code())) {
            return Err(MatterError::UnsupportedCodeError(String::from(base.code())));
        }

        Ok(Cigar {
            base,
            verfer: None
        })
    }


    fn from_qb2(data: &mut Vec<u8>, strip: Option<bool>) -> Result<Self, MatterError> {
        let base = BaseMatter::from_qb2(data, strip)?;
        if !non_trans_dex::TUPLE.contains(&(base.code())) {
            return Err(MatterError::UnsupportedCodeError(String::from(base.code())));
        }

        Ok(Cigar {
            base,
            verfer: None
        })
    }
}

impl Matter for Cigar {
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
