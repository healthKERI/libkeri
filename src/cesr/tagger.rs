use crate::cesr::BaseMatter;
use crate::Matter;
use std::any::Any;

/// Tagger is subclass of Matter, cryptographic material, for compact special
/// fixed size primitive with non-empty soft part and empty raw part.
///
/// Tagger provides a more compact representation of small Base64 values in
/// as soft part of code rather than would be obtained by by using a small raw
/// part whose ASCII representation is converted to Base64.
pub struct Tagger {
    base: BaseMatter,
}

impl Tagger {}

impl Matter for Tagger {
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
