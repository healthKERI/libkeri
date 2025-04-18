use std::any::Any;
use crate::cesr::BaseMatter;
use crate::Matter;

/// Ilker is subclass of Tagger, cryptographic material, for formatted
/// message types (ilks) in Base64. Leverages Tagger support compact special
/// fixed size primitives with non-empty soft part and empty raw part.
///
/// Ilker provides a more compact representation than would be obtained by
/// converting the raw ASCII representation to Base64.

pub struct Ilker {
    base: BaseMatter,
}

impl Ilker {

}

impl Matter for Ilker {
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
