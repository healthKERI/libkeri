use std::any::Any;
use crate::cesr::BaseMatter;
use crate::Matter;

///     Labeler is subclass of Matter for CESR native field map labels and/or generic
///     textual field values. Labeler auto sizes the instance code to minimize
///     the total encoded size of associated field label or textual field value. a small raw

pub struct Labeler {
    base: BaseMatter,
}

impl Labeler {

}

impl Matter for Labeler {
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
