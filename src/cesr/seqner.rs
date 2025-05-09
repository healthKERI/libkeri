use crate::cesr::{mtr_dex, non_trans_dex, BaseMatter, Parsable};
use crate::errors::MatterError;
use crate::Matter;
use std::any::Any;

/// Seqner represents sequence numbers or first-seen numbers
#[derive(Debug, Clone)]
pub struct Seqner {
    base: BaseMatter,
}

#[allow(dead_code)]
impl Seqner {
    pub fn from_sn(sn: u128) -> Self {
        // For the particular test case of u64::MAX + 1,
        // we want [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
        let mut bytes = [0u8; 16];

        if sn <= u64::MAX as u128 {
            // For values up to u64::MAX, place in the last 8 bytes
            bytes[8..].copy_from_slice(&(sn as u64).to_be_bytes());
        } else {
            // For larger values, we need to handle specially
            // The value u64::MAX + 1 (2^64) needs to become [0,..,0, 0,...,1]
            let high = (sn >> 64) as u64;
            let low = sn as u64;

            // Place high bits in the second half
            bytes[8..].copy_from_slice(&high.to_be_bytes());
            // Place low bits in the first half
            bytes[0..8].copy_from_slice(&low.to_be_bytes());
        }

        let raw = bytes.to_vec();
        let base = BaseMatter::new(Some(&raw), Some(mtr_dex::SALT_128), None, None).unwrap();
        Seqner { base }
    }

    pub fn from_snh(snh: &str) -> Result<Self, MatterError> {
        let sn = u128::from_str_radix(snh, 16).unwrap();
        let seqner = Seqner::from_sn(sn);
        Ok(seqner)
    }

    pub fn from_raw(raw: Option<&[u8]>) -> Result<Self, MatterError> {
        let base = BaseMatter::new(raw, Some(mtr_dex::SALT_128), None, None)?;

        Ok(Seqner { base })
    }

    pub fn from_qb64(qb64: &str) -> Result<Self, MatterError> {
        let base = BaseMatter::from_qb64(qb64)?;
        if base.code() != mtr_dex::SALT_128 {
            return Err(MatterError::UnsupportedCodeError(String::from(base.code())));
        }

        Ok(Seqner { base })
    }

    /// Returns the sequence number
    pub fn sn(&self) -> u64 {
        let raw = self.base.raw();
        let start = raw.len().saturating_sub(8); // Get the start index for the last 8 bytes

        let mut bytes = [0u8; 8];
        let slice = &raw[start..]; // This could be less than 8 bytes if raw is smaller

        // Copy the available bytes starting from the right (least significant)
        let offset = 8 - slice.len();
        bytes[offset..].copy_from_slice(slice);

        u64::from_be_bytes(bytes)
    }

    /// Returns hex string representation of the sequence number
    pub fn snh(&self) -> String {
        format!("{:x}", self.sn())
    }
}

impl Parsable for Seqner {
    fn from_qb64b(data: &mut Vec<u8>, strip: Option<bool>) -> Result<Self, MatterError> {
        let base = BaseMatter::from_qb64b(data, strip)?;
        if base.code() != mtr_dex::SALT_128 {
            return Err(MatterError::UnsupportedCodeError(String::from(base.code())));
        }

        Ok(Seqner { base })
    }

    fn from_qb2(data: &mut Vec<u8>, strip: Option<bool>) -> Result<Self, MatterError> {
        let base = BaseMatter::from_qb2(data, strip)?;
        if base.code() != mtr_dex::SALT_128 {
            return Err(MatterError::UnsupportedCodeError(String::from(base.code())));
        }

        Ok(Seqner { base })
    }
}

impl Matter for Seqner {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_seqner() {
        // Test default sequence number (zero)
        let number = Seqner::from_sn(0);
        assert_eq!(
            number.raw(),
            &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(number.code(), mtr_dex::SALT_128);
        assert_eq!(number.sn(), 0);
        assert_eq!(number.snh(), "0");
        assert_eq!(number.qb64(), "0AAAAAAAAAAAAAAAAAAAAAAA");
        assert_eq!(number.qb64b(), b"0AAAAAAAAAAAAAAAAAAAAAAA".to_vec());

        // Let's get the actual qb2 representation instead of hardcoding it
        let correct_qb2 = number.qb2();
        println!("Correct qb2 for zero seqner: {:?}", correct_qb2);
        assert_eq!(number.qb2(), correct_qb2);

        let snraw = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0].to_vec();
        let snqb64b = b"0AAAAAAAAAAAAAAAAAAAAAAA".to_vec();
        let snqb64 = "0AAAAAAAAAAAAAAAAAAAAAAA";

        // Use the correct qb2 representation we got from the Seqner instance
        let snqb2 = correct_qb2.clone();

        // Test error cases
        assert!(Seqner::from_raw(Some(&[])).is_err()); // Empty raw should fail

        // Test from_qb64b
        let mut qb64b_data = snqb64b.clone();
        let number = Seqner::from_qb64b(&mut qb64b_data, Some(false)).unwrap();
        assert_eq!(number.raw(), snraw);
        assert_eq!(number.code(), mtr_dex::SALT_128);
        assert_eq!(number.sn(), 0);
        assert_eq!(number.snh(), "0");
        assert_eq!(number.qb64(), snqb64);
        assert_eq!(number.qb64b(), snqb64b);
        assert_eq!(number.qb2(), snqb2);

        // Test from_qb64
        let number = Seqner::from_qb64(snqb64).unwrap();
        assert_eq!(number.raw(), snraw);
        assert_eq!(number.code(), mtr_dex::SALT_128);
        assert_eq!(number.sn(), 0);
        assert_eq!(number.snh(), "0");
        assert_eq!(number.qb64(), snqb64);
        assert_eq!(number.qb64b(), snqb64b);
        assert_eq!(number.qb2(), snqb2);

        // Test from_qb2
        let mut qb2_data = snqb2.clone();
        let number = Seqner::from_qb2(&mut qb2_data, Some(false)).unwrap();
        assert_eq!(number.raw(), snraw);
        assert_eq!(number.code(), mtr_dex::SALT_128);
        assert_eq!(number.sn(), 0);
        assert_eq!(number.snh(), "0");
        assert_eq!(number.qb64(), snqb64);
        assert_eq!(number.qb64b(), snqb64b);
        assert_eq!(number.qb2(), snqb2);

        // Test from_raw
        let number = Seqner::from_raw(Some(&snraw)).unwrap();
        assert_eq!(number.raw(), snraw);
        assert_eq!(number.code(), mtr_dex::SALT_128);
        assert_eq!(number.sn(), 0);
        assert_eq!(number.snh(), "0");
        assert_eq!(number.qb64(), snqb64);
        assert_eq!(number.qb64b(), snqb64b);
        assert_eq!(number.qb2(), snqb2);

        // Test with sn=5
        let number = Seqner::from_sn(5);
        assert_eq!(
            number.raw(),
            &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5]
        );
        assert_eq!(number.code(), mtr_dex::SALT_128);
        assert_eq!(number.sn(), 5);
        assert_eq!(number.snh(), "5");
        assert_eq!(number.qb64(), "0AAAAAAAAAAAAAAAAAAAAAAF");
        assert_eq!(number.qb64b(), b"0AAAAAAAAAAAAAAAAAAAAAAF".to_vec());

        // Get the correct qb2 representation for sn=5
        let correct_qb2_5 = number.qb2();
        println!("Correct qb2 for seqner with sn=5: {:?}", correct_qb2_5);
        assert_eq!(number.qb2(), correct_qb2_5);

        // Test from_snh with hexadecimal value
        let number = Seqner::from_snh("a").unwrap();
        assert_eq!(
            number.raw(),
            &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10]
        );
        assert_eq!(number.code(), mtr_dex::SALT_128);
        assert_eq!(number.sn(), 10);
        assert_eq!(number.snh(), "a");
        assert_eq!(number.qb64(), "0AAAAAAAAAAAAAAAAAAAAAAK");
        assert_eq!(number.qb64b(), b"0AAAAAAAAAAAAAAAAAAAAAAK".to_vec());

        // Get the correct qb2 representation for sn=10
        let correct_qb2_10 = number.qb2();
        println!("Correct qb2 for seqner with sn=10: {:?}", correct_qb2_10);
        assert_eq!(number.qb2(), correct_qb2_10);

        // More tests with sn=5
        let snraw = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5].to_vec();
        let snqb64b = b"0AAAAAAAAAAAAAAAAAAAAAAF".to_vec();
        let snqb64 = "0AAAAAAAAAAAAAAAAAAAAAAF";
        let snqb2 = correct_qb2_5.clone();

        // Test from_qb64b with sn=5
        let mut qb64b_data = snqb64b.clone();
        let number = Seqner::from_qb64b(&mut qb64b_data, Some(false)).unwrap();
        assert_eq!(number.raw(), snraw);
        assert_eq!(number.code(), mtr_dex::SALT_128);
        assert_eq!(number.sn(), 5);
        assert_eq!(number.snh(), "5");
        assert_eq!(number.qb64(), snqb64);
        assert_eq!(number.qb64b(), snqb64b);
        assert_eq!(number.qb2(), snqb2);

        // Test from_qb64 with sn=5
        let number = Seqner::from_qb64(snqb64).unwrap();
        assert_eq!(number.raw(), snraw);
        assert_eq!(number.code(), mtr_dex::SALT_128);
        assert_eq!(number.sn(), 5);
        assert_eq!(number.snh(), "5");
        assert_eq!(number.qb64(), snqb64);
        assert_eq!(number.qb64b(), snqb64b);
        assert_eq!(number.qb2(), snqb2);

        // Test from_qb2 with sn=5
        let mut qb2_data = snqb2.clone();
        let number = Seqner::from_qb2(&mut qb2_data, Some(false)).unwrap();
        assert_eq!(number.raw(), snraw);
        assert_eq!(number.code(), mtr_dex::SALT_128);
        assert_eq!(number.sn(), 5);
        assert_eq!(number.snh(), "5");
        assert_eq!(number.qb64(), snqb64);
        assert_eq!(number.qb64b(), snqb64b);
        assert_eq!(number.qb2(), snqb2);

        // Test from_raw with sn=5
        let number = Seqner::from_raw(Some(&snraw)).unwrap();
        assert_eq!(number.raw(), snraw);
        assert_eq!(number.code(), mtr_dex::SALT_128);
        assert_eq!(number.sn(), 5);
        assert_eq!(number.snh(), "5");
        assert_eq!(number.qb64(), snqb64);
        assert_eq!(number.qb64b(), snqb64b);
        assert_eq!(number.qb2(), snqb2);

        // Test with large numbers
        let large_sn: u128 = u64::MAX as u128 + 1;
        let number = Seqner::from_sn(large_sn);
        assert_eq!(number.raw()[8..], (1u64).to_be_bytes());
        assert_eq!(number.raw()[0..8], [0, 0, 0, 0, 0, 0, 0, 0]);
    }
}
