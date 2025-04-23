use crate::cesr::{dig_dex, mtr_dex, BaseMatter, Parsable};
use crate::errors::MatterError;
use crate::Matter;
use blake2::{Blake2b512, Blake2s256, Digest as Blake2Digest};
use blake3::Hasher as Blake3Hasher;
use sha2::{Sha256, Sha512};
use sha3::{Digest as Sha3Digest, Sha3_256, Sha3_512};
use std::any::Any;

///  Diger is Matter subclass with method to verify digest of serialization
#[derive(Debug, Clone)]
pub struct Diger {
    base: BaseMatter,
}

impl Diger {
    pub fn new(
        raw: Option<&[u8]>,
        code: Option<&str>,
        soft: Option<&str>,
        rize: Option<usize>,
    ) -> Result<Self, MatterError> {
        let code = code.unwrap_or_else(|| mtr_dex::BLAKE3_256);
        if !dig_dex::TUPLE.contains(&(code)) {
            return Err(MatterError::UnsupportedCodeError(String::from(code)));
        }

        let base = BaseMatter::new(raw, Some(code), soft, rize)?;
        Ok(Diger { base })
    }

    pub fn from_raw(raw: Option<&[u8]>) -> Result<Self, MatterError> {
        let base = BaseMatter::new(raw, Some(mtr_dex::BLAKE3_256), None, None)?;

        Ok(Diger { base })
    }

    pub fn from_qb64(qb64: &str) -> Result<Self, MatterError> {
        let base = BaseMatter::from_qb64(qb64)?;
        if !dig_dex::TUPLE.contains(&(base.code())) {
            return Err(MatterError::UnsupportedCodeError(String::from(base.code())));
        }

        Ok(Diger { base })
    }

    pub fn from_ser(ser: &[u8], code: Option<&str>) -> Result<Self, MatterError> {
        let code = code.unwrap_or_else(|| mtr_dex::BLAKE3_256);
        Diger::from_ser_and_code(ser, code)
    }

    pub fn from_ser_and_code(ser: &[u8], code: &str) -> Result<Self, MatterError> {
        let raw = Diger::digest(ser, code)?;
        let base = BaseMatter::new(Some(&raw), Some(code), None, None)?;
        Ok(Diger { base })
    }

    pub fn digest(ser: &[u8], code: &str) -> Result<Vec<u8>, MatterError> {
        match code {
            code if code == dig_dex::BLAKE3_256 => {
                let result = Diger::digest_blake3_256(ser)?;
                Ok(result.to_vec())
            }
            code if code == dig_dex::BLAKE3_512 => {
                let result = Diger::digest_blake3_512(ser)?;
                Ok(result.to_vec())
            }
            code if code == dig_dex::SHA3_256 => {
                let result = Diger::digest_sha3_256(ser)?;
                Ok(result.to_vec())
            }
            code if code == dig_dex::SHA2_256 => {
                let result = Diger::digest_sha2_256(ser)?;
                Ok(result.to_vec())
            }
            code if code == dig_dex::SHA3_512 => {
                let result = Diger::digest_sha3_512(ser)?;
                Ok(result.to_vec())
            }
            code if code == dig_dex::SHA2_512 => {
                let result = Diger::digest_sha2_512(ser)?;
                Ok(result.to_vec())
            }
            code if code == dig_dex::BLAKE2S_256 => {
                let result = Diger::digest_blake2s_256(ser)?;
                Ok(result.to_vec())
            }
            code if code == dig_dex::BLAKE2B_512 => {
                let result = Diger::digest_blake2b_512(ser)?;
                Ok(result.to_vec())
            }
            // code if code == dig_dex::BLAKE2B_256 => {
            //     let result = Diger::digest_blake2b_256(ser)?;
            //     Ok(result.to_vec())
            // },
            // This should never happen because we validate in the constructor
            _ => Err(MatterError::UnsupportedCodeError(String::from(code))),
        }
    }

    /// Calculate Blake3 256-bit hash (default output size of Blake3)
    fn digest_blake3_256(data: &[u8]) -> Result<[u8; 32], MatterError> {
        let result = blake3::hash(data).into();
        Ok(result)
    }

    /// Calculate Blake2b 512-bit hash
    fn digest_blake2b_512(data: &[u8]) -> Result<[u8; 64], MatterError> {
        let mut hasher = Blake2b512::new();
        hasher.update(data);
        let result = hasher.finalize();
        let mut digest = [0u8; 64];
        digest.copy_from_slice(&result);
        Ok(digest)
    }

    // /// Calculate Blake2b 256-bit hash
    // fn digest_blake2b_256(data: &[u8]) -> Result<[u8; 32], MatterError> {
    //     let mut hasher = Blake2b::new_with_params(32);
    //     hasher.update(data);
    //     let result = hasher.finalize();
    //     let mut digest = [0u8; 32];
    //     digest.copy_from_slice(&result[..32]);
    //     Ok(digest)
    // }
    //

    /// Calculate Blake2s 256-bit hash
    fn digest_blake2s_256(data: &[u8]) -> Result<[u8; 32], MatterError> {
        let mut hasher = Blake2s256::new();
        hasher.update(data);
        let result = hasher.finalize();
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&result);
        Ok(digest)
    }

    /// Calculate Blake3 512-bit hash
    fn digest_blake3_512(data: &[u8]) -> Result<[u8; 64], MatterError> {
        let mut hasher = Blake3Hasher::new();
        hasher.update(data);
        let mut digest = [0u8; 64];
        hasher.finalize_xof().fill(&mut digest);
        Ok(digest)
    }
    /// Calculate SHA3-256 hash
    fn digest_sha3_256(data: &[u8]) -> Result<[u8; 32], MatterError> {
        let mut hasher = Sha3_256::new();
        hasher.update(data);
        let result = hasher.finalize();
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&result);
        Ok(digest)
    }

    /// Calculate SHA2-256 hash
    fn digest_sha2_256(data: &[u8]) -> Result<[u8; 32], MatterError> {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let result = hasher.finalize();
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&result);
        Ok(digest)
    }

    /// Calculate SHA3-512 hash
    fn digest_sha3_512(data: &[u8]) -> Result<[u8; 64], MatterError> {
        let mut hasher = Sha3_512::new();
        hasher.update(data);
        let result = hasher.finalize();
        let mut digest = [0u8; 64];
        digest.copy_from_slice(&result);
        Ok(digest)
    }

    /// Calculate SHA2-512 hash
    fn digest_sha2_512(data: &[u8]) -> Result<[u8; 64], MatterError> {
        let mut hasher = Sha512::new();
        hasher.update(data);
        let result = hasher.finalize();
        let mut digest = [0u8; 64];
        digest.copy_from_slice(&result);
        Ok(digest)
    }

    fn verify(&self, ser: &[u8]) -> bool {
        match Diger::digest(ser, self.base.code()) {
            Ok(raw) => self.base.raw() == raw.as_slice(),
            Err(_) => false,
        }
    }

    fn compare_with_diger(&self, ser: &[u8], other: &Self) -> bool {
        if self.base.qb64() == other.base.qb64() {
            return true;
        }

        if self.code() == other.code() {
            return false;
        }

        other.verify(ser) && self.verify(ser)
    }

    fn compare_with_qb64(&self, ser: &[u8], other: &str) -> bool {
        self.compare_with_diger(ser, &Diger::from_qb64(other).unwrap())
    }

    fn compare_with_qb64b(&self, ser: &[u8], other: &[u8]) -> bool {
        self.compare_with_diger(ser, &Diger::from_qb64b(&mut other.to_vec(), None).unwrap())
    }
}

impl Parsable for Diger {
    fn from_qb64b(data: &mut Vec<u8>, strip: Option<bool>) -> Result<Self, MatterError> {
        let base = BaseMatter::from_qb64b(data, strip)?;
        if !dig_dex::TUPLE.contains(&(base.code())) {
            return Err(MatterError::UnsupportedCodeError(String::from(base.code())));
        }

        Ok(Diger { base })
    }

    fn from_qb2(data: &mut Vec<u8>, strip: Option<bool>) -> Result<Self, MatterError> {
        let base = BaseMatter::from_qb2(data, strip)?;
        if !dig_dex::TUPLE.contains(&(base.code())) {
            return Err(MatterError::UnsupportedCodeError(String::from(base.code())));
        }

        Ok(Diger { base })
    }
}

impl Matter for Diger {
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
    use crate::cesr::raw_size;
    use blake2::{Blake2b512, Blake2s256, Digest};
    use blake3;
    use sha2::Sha256;
    use sha3::Sha3_256;

    #[test]
    fn test_diger() {
        // Test that the keyspace of Diger.Digests is the same as codes in DigDex
        // (this would need to be adapted to your specific Rust implementation)
        // assert_eq!(DigDex.keys().collect::<HashSet<_>>(), Diger::DIGESTS.keys().collect::<HashSet<_>>());
        // Test EmptyMaterialError
        let result = Diger::new(None, None, None, None);
        assert!(result.is_err());

        // Create something to digest and verify
        let ser = b"abcdefghijklmnopqrstuvwxyz0123456789";

        // Test invalid code error
        let hash = blake3::hash(ser);
        let dig = hash.as_bytes();
        let result = Diger::new(Some(&dig[..]), Some(mtr_dex::ED25519), None, None);
        assert!(result.is_err());

        // Test default constructor with raw digest
        let diger = Diger::new(Some(&dig[..]), None, None, None).unwrap();
        assert_eq!(diger.code(), mtr_dex::BLAKE3_256);
        assert_eq!(diger.raw().len(), raw_size(diger.code()).unwrap());
        assert!(diger.verify(ser));
        assert!(!diger.verify(&[ser.to_vec(), b"ABCDEF".to_vec()].concat()));

        // Test with explicit code
        let diger = Diger::new(Some(&dig[..]), Some(mtr_dex::BLAKE3_256), None, None).unwrap();
        assert_eq!(diger.code(), mtr_dex::BLAKE3_256);
        assert_eq!(diger.raw().len(), raw_size(diger.code()).unwrap());
        assert!(diger.verify(ser));

        // Test constructor with serialization
        let diger = Diger::from_ser(ser, None).unwrap();
        assert_eq!(diger.code(), mtr_dex::BLAKE3_256);
        assert_eq!(diger.raw().len(), raw_size(diger.code()).unwrap());
        assert!(diger.verify(ser));
        assert_eq!(
            diger.qb64b(),
            b"ELC5L3iBVD77d_MYbYGGCUQgqQBju1o4x1Ud-z2sL-ux"
        );

        // Test constructor with qb64b
        let digb = b"ELC5L3iBVD77d_MYbYGGCUQgqQBju1o4x1Ud-z2sL-ux";
        let dig = "ELC5L3iBVD77d_MYbYGGCUQgqQBju1o4x1Ud-z2sL-ux";
        let diger = Diger::from_qb64b(&mut digb.to_vec(), None).unwrap();
        assert_eq!(diger.qb64b(), digb);
        assert_eq!(diger.qb64(), dig);
        assert_eq!(diger.code(), mtr_dex::BLAKE3_256);
        //
        // Test constructor with qb64
        let diger = Diger::from_qb64(dig).unwrap();
        assert_eq!(diger.qb64(), dig);
        assert_eq!(diger.qb64b(), digb);
        assert_eq!(diger.code(), mtr_dex::BLAKE3_256);

        // Test base64 encoding/decoding
        // let pig = b"sLkveIFUPvt38xhtgYYJRCCpAGO7WjjHVR37Pawv67E=";
        // let raw = decode_b64(str::from_utf8(pig).unwrap()).unwrap();
        // assert_eq!(str::from_utf8(pig).unwrap(), &encode_b64(&raw));

        // Test Blake2b_512
        let mut hasher = Blake2b512::new();
        hasher.update(ser);
        let dig = hasher.finalize()[..].to_vec();
        let diger = Diger::new(Some(&dig[..]), Some(mtr_dex::BLAKE2B_512), None, None).unwrap();
        assert_eq!(diger.code(), mtr_dex::BLAKE2B_512);
        assert_eq!(diger.raw().len(), raw_size(diger.code()).unwrap());
        assert!(diger.verify(ser));

        let diger = Diger::from_ser(ser, Some(mtr_dex::BLAKE2B_512)).unwrap();
        assert_eq!(diger.code(), mtr_dex::BLAKE2B_512);
        assert_eq!(diger.raw().len(), raw_size(diger.code()).unwrap());
        assert!(diger.verify(ser));
        //
        // Test Blake2s_256
        let mut hasher = Blake2s256::new();
        hasher.update(ser);
        let dig = hasher.finalize();
        let diger = Diger::new(Some(&dig[..]), Some(mtr_dex::BLAKE2S_256), None, None).unwrap();
        assert_eq!(diger.code(), mtr_dex::BLAKE2S_256);
        assert_eq!(diger.raw().len(), raw_size(diger.code()).unwrap());
        assert!(diger.verify(ser));
        //
        let diger = Diger::from_ser(ser, Some(mtr_dex::BLAKE2S_256)).unwrap();
        assert_eq!(diger.code(), mtr_dex::BLAKE2S_256);
        assert_eq!(diger.raw().len(), raw_size(diger.code()).unwrap());
        assert!(diger.verify(ser));

        // Test SHA3_256
        let mut hasher = Sha3_256::new();
        hasher.update(ser);
        let dig = hasher.finalize();
        let diger = Diger::new(Some(&dig), Some(mtr_dex::SHA3_256), None, None).unwrap();
        assert_eq!(diger.code(), mtr_dex::SHA3_256);
        assert_eq!(diger.raw().len(), raw_size(diger.code()).unwrap());
        assert!(diger.verify(ser));

        let diger = Diger::from_ser(ser, Some(mtr_dex::SHA3_256)).unwrap();
        assert_eq!(diger.code(), mtr_dex::SHA3_256);
        assert_eq!(diger.raw().len(), raw_size(diger.code()).unwrap());
        assert!(diger.verify(ser));

        // Test SHA2_256
        let mut hasher = Sha256::new();
        hasher.update(ser);
        let dig = hasher.finalize();
        let diger = Diger::new(Some(&dig), Some(mtr_dex::SHA2_256), None, None).unwrap();
        assert_eq!(diger.code(), mtr_dex::SHA2_256);
        assert_eq!(diger.raw().len(), raw_size(diger.code()).unwrap());
        assert!(diger.verify(ser));

        let diger = Diger::from_ser(ser, Some(mtr_dex::SHA2_256)).unwrap();
        assert_eq!(diger.code(), mtr_dex::SHA2_256);
        assert_eq!(diger.raw().len(), raw_size(diger.code()).unwrap());
        assert!(diger.verify(ser));

        // Test comparison functionality
        let diger0 = Diger::from_ser(ser, None).unwrap(); // default code
        let diger1 = Diger::from_ser(ser, Some(mtr_dex::SHA3_256)).unwrap();
        let diger2 = Diger::from_ser(ser, Some(mtr_dex::BLAKE2B_512)).unwrap();
        //
        assert!(diger0.compare_with_diger(ser, &diger1));
        assert!(diger0.compare_with_diger(ser, &diger2));
        assert!(diger1.compare_with_diger(ser, &diger2));

        assert!(diger0.compare_with_qb64(ser, &diger1.qb64()));
        assert!(diger0.compare_with_qb64b(ser, &diger2.qb64b()));
        assert!(diger1.compare_with_qb64(ser, &diger2.qb64()));

        let ser1 = b"ABCDEFGHIJKLMNOPQSTUVWXYXZabcdefghijklmnopqrstuvwxyz0123456789";

        // Codes match but content different
        let diger_ser1 = Diger::from_ser(ser1, None).unwrap();
        assert!(!diger0.compare_with_diger(ser, &diger_ser1));
        assert!(!diger0.compare_with_qb64(ser, &diger_ser1.qb64()));

        // Codes don't match and content different
        let diger_ser1_sha3 = Diger::from_ser(ser1, Some(mtr_dex::SHA3_256)).unwrap();
        assert!(!diger0.compare_with_diger(ser, &diger_ser1_sha3));
        assert!(!diger0.compare_with_qb64b(ser, &diger_ser1_sha3.qb64b()));
    }
}
