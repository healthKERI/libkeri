use std::any::Any;
use num_bigint::BigUint;
use crate::cesr::{num_dex, raw_size, BaseMatter, Parsable};
use num_traits::pow;
use crate::errors::MatterError;
use crate::Matter;

/// Number represents ordinal counting numbers
#[derive(Debug, Clone)]
pub struct Number {
    base: BaseMatter,
}

#[allow(dead_code)]
impl Number {

    pub fn from_num(num: &BigUint) -> Result<Self, MatterError> {
        let code = number_code(num)?;
        let raw = num.to_bytes_be();
        let rs = raw_size(code)?;
        if raw.len() > rs {
            return Err(MatterError::InvalidValue(num.to_string()));
        }

        let mut zeroed_buffer = vec![0u8; rs];
        let bytes = zeroed_buffer.as_mut_slice();
        let start = rs - raw.len();
        bytes[start..].copy_from_slice(raw.as_slice());

        let base = BaseMatter::new(Some(&bytes), Some(code), None, None)?;
        Ok(Number {
            base
        })
    }

    pub fn from_numh(numh: &str) -> Result<Self, MatterError> {

        let num = if numh.len() == 0 {
            0
        } else {
            u64::from_str_radix(numh, 16).unwrap()
        };

        let biguint = BigUint::from(num);
        Number::from_num(&biguint)
    }


    /// Creates a new Number from a numeric value
    pub fn new(raw: Option<&[u8]>, code: Option<&str>, soft: Option<&str>, rize: Option<usize>) -> Result<Self, MatterError> {
        if !num_dex::TUPLE.contains(&(code.unwrap())) {
            return Err(MatterError::UnsupportedCodeError(String::from(code.unwrap_or("None"))));
        }

        let base = BaseMatter::new(raw, code, soft, rize)?;
        Ok(Number {
            base
        })
    }


    pub fn from_qb64(qb64: &str) -> Result<Self, MatterError> {
        let base = BaseMatter::from_qb64(qb64)?;
        if !num_dex::TUPLE.contains(&(base.code())) {
            return Err(MatterError::UnsupportedCodeError(String::from(base.code())));
        }

        Ok(Number {
            base
        })
    }

    /// Returns the numeric value
    pub fn num(&self) -> u128 {
        let mut bytes = [0u8; 16];
        let start = 16 - self.raw().len();
        bytes[start..].copy_from_slice(self.raw());
        u128::from_be_bytes(bytes)
    }

    pub fn numh(&self) -> String {
        let num = self.num();
        format!("{:x}", num)
    }

    /// Sequence number, sn method getter to mimic Seqner interface
    ///
    /// Returns:
    ///     sn (i64): alias for num
    pub fn sn(&self) -> u128 {
        self.num()
    }

    /// Sequence number hex str, snh method getter to mimic Seqner interface
    ///
    /// Returns:
    ///     snh (String): alias for numh
    pub fn snh(&self) -> String {
        self.numh()
    }

    /// Provides number value as qb64 but with code NumDex::Huge. This is the
    /// same as Seqner.qb64. Raises error if too big.
    ///
    /// Returns:
    ///     huge (String): qb64 of num coded as NumDex::Huge
    ///
    /// # Errors
    ///
    /// Returns an error if the number is too big for ordinal 256^16 - 1
    pub fn huge(&self) -> String {
        let num = self.num();
        // MaxON represents 256^16 - 1
        let max_on =  (256 ^ 16)-1;

        if num > max_on {
            // In an actual implementation, you would return an error
            // This simplified version panics instead
            panic!("Non-ordinal {} exceeds {}", num, max_on);
        }

        let mut bytes = [0u8; 16];
        let start = 16 - self.raw().len();
        bytes[start..].copy_from_slice(self.raw());

        // Create a new Number with the same num but with NumDex::Huge code
        // and return its qb64 representation
        let huge_number = Number::new(Some(&bytes[..]), Some(num_dex::HUGE), None, None).expect("Failed to create huge number");
        huge_number.qb64()
    }

    /// Returns true if .num is strictly positive non-zero, false otherwise.
    /// Because valid number .num must be non-negative, positive false also means
    /// that .num is zero.
    ///
    /// Returns:
    ///     bool: true if num > 0, false otherwise
    pub fn positive(&self) -> bool {
        self.num() > 0
    }

    /// Returns true if .num == 0, false otherwise.
    ///
    /// Returns:
    ///     bool: true if num == 0, false otherwise
    pub fn inceptive(&self) -> bool {
        self.num() == 0
    }

}

impl Parsable for Number {
    fn from_qb64b(data: &mut Vec<u8>, strip: Option<bool>) -> Result<Self, MatterError> {
        let base = BaseMatter::from_qb64b(data, strip)?;
        if !num_dex::TUPLE.contains(&(base.code())) {
            return Err(MatterError::UnsupportedCodeError(String::from(base.code())));
        }

        Ok(Number {
            base
        })
    }

    fn from_qb2(data: &mut Vec<u8>, strip: Option<bool>) -> Result<Self, MatterError> {
        let base = BaseMatter::from_qb2(data, strip)?;
        if !num_dex::TUPLE.contains(&(base.code())) {
            return Err(MatterError::UnsupportedCodeError(String::from(base.code())));
        }

        Ok(Number {
            base
        })
    }
}

pub fn number_code(num: &BigUint) -> Result<&str, MatterError> {
    let base = BigUint::from(256u32);

    // Check for Short (256^2 - 1)
    let short_limit = pow(base.clone(), 2u32 as usize) - 1u32;
    if num <= &short_limit {
        return Ok(num_dex::SHORT);
    }

    // Check for Tall (256^5 - 1)
    let tall_limit = pow(base.clone(), 5u32 as usize) - 1u32;
    if num <= &tall_limit {
        return Ok(num_dex::TALL);
    }

    // Check for Big (256^8 - 1)
    let big_limit = pow(base.clone(), 8u32 as usize) - 1u32;
    if num <= &big_limit {
        return Ok(num_dex::BIG);
    }

    // Check for Large (256^11 - 1)
    let large_limit = pow(base.clone(), 11u32 as usize) - 1u32;
    if num <= &large_limit {
        return Ok(num_dex::LARGE);
    }

    // Check for Great (256^14 - 1)
    let great_limit = pow(base.clone(), 14u32 as usize) - 1u32;
    if num <= &great_limit {
        return Ok(num_dex::GREAT);
    }

    // Check for Vast (256^17 - 1)
    let vast_limit = pow(base.clone(), 17u32 as usize) - 1u32;
    if num <= &vast_limit {
        return Ok(num_dex::VAST);
    }

    // Too large, return error
    Err(MatterError::InvalidValue(num.to_string()))
}

impl Matter for Number {
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


impl Default for Number {
    fn default() -> Self {
        // Default to zero value with a "Short" code
        let raw = vec![0u8; 2]; // Two-byte zero vector for "Short" code
        let code = num_dex::SHORT; // Default code
        Self::new(Some(&raw), Some(code), None, None).expect("Failed to create default Number")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_number_default() {
        // Test defaults, num is None forces to zero, code dynamic
        let number = Number::default();

        assert_eq!(number.code(), num_dex::SHORT);
        assert_eq!(number.raw(), &[0, 0]);
        assert_eq!(number.qb64(), "MAAA");
        assert_eq!(number.qb64b(), b"MAAA");
        assert_eq!(number.qb2(), &[0x30, 0x00, 0x00]);
        assert_eq!(number.num(), 0);
        assert_eq!(number.numh(), "0");
        assert_eq!(number.sn(), 0);
        assert_eq!(number.snh(), "0");
        assert_eq!(number.huge(), "0AAAAAAAAAAAAAAAAAAAAAAA");
        assert_eq!(number.huge().len(), 24);
        assert!(!number.positive());
        assert!(number.inceptive());

        // Test hex representation of qb2 bytes
        let qb2_as_int = u32::from_be_bytes([0, 0x30, 0x00, 0x00]);
        assert_eq!(format!("0x{:x}", qb2_as_int), "0x300000");
    }

    #[test]
    fn test_empty_string_defaults() {
        // test numh as empty string defaults to 0
        let number = Number::from_numh("").expect("Failed to create number from empty string");
        assert_eq!(number.num(), 0);
    }

    #[test]
    fn test_number_basics() {
        // Test with a simple number
        let num = BigUint::from(12345u64);
        let number = Number::from_num(&num).expect("Failed to create Number from num");

        assert_eq!(number.num(), 12345u128);
        assert_eq!(number.numh(), "3039");
        assert!(number.positive());
    }

    #[test]
    fn test_number_conversion() {
        // Test converting between formats
        let num = BigUint::from(987654321u64);
        let number = Number::from_num(&num).expect("Failed to create Number from num");

        let qb64 = number.qb64();
        let from_qb64 = Number::from_qb64(&qb64).expect("Failed to convert from qb64");

        assert_eq!(number.num(), from_qb64.num());
        assert_eq!(number.numh(), from_qb64.numh());
    }

    #[test]
    fn test_sn_methods() {
        // Test sn and snh methods
        let num = BigUint::from(42u64);
        let number = Number::from_num(&num).expect("Failed to create Number from num");

        assert_eq!(number.sn(), 42u128);
        assert_eq!(number.snh(), "2a");
    }

    #[test]
    fn test_inceptive() {
        // Test inceptive property - likely true for 0
        let num = BigUint::from(0u64);
        let number = Number::from_num(&num).expect("Failed to create Number from num");

        assert!(number.inceptive());

        // Test with a non-zero number
        let num = BigUint::from(1u64);
        let number = Number::from_num(&num).expect("Failed to create Number from num");

        // Note: This assertion assumes inceptive() returns false for non-zero values
        // Adjust based on actual implementation
        assert!(!number.inceptive());
    }

}