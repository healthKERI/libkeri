use crate::errors::MatterError;
use base64::{engine::general_purpose, Engine};
use num_bigint::BigUint;
use num_traits::ToPrimitive;
use once_cell::sync::Lazy;
use std::any::Any;
use std::collections::HashMap;
use std::fmt::Display;
use std::{fmt, str};

pub mod bexter;
pub mod cigar;
pub mod counting;
pub mod dater;
pub mod diger;
pub mod ilker;
pub mod indexing;
pub mod labeler;
pub mod number;
pub mod pather;
pub mod prefixer;
pub mod saider;
pub mod seqner;
pub mod signing;
pub mod tagger;
pub mod texter;
pub mod tholder;
pub mod verfer;

#[derive(Debug, Clone, PartialEq)]
pub struct Versionage {
    pub major: u32,
    pub minor: u32,
}
pub const VERSION: Versionage = Versionage { major: 1, minor: 0 };
#[allow(dead_code)]
pub const VRSN_1_0: Versionage = Versionage { major: 1, minor: 0 };
#[allow(dead_code)]
pub const VRSN_2_0: Versionage = Versionage { major: 2, minor: 0 };

pub const PAD: &str = "_";

impl fmt::Display for Versionage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}", self.major, self.minor)
    }
}

/// Maps Base64 index to corresponding character
pub static B64_CHR_BY_IDX: Lazy<HashMap<u8, char>> = Lazy::new(|| {
    let mut map = HashMap::new();

    // A-Z: ASCII 65-90, indices 0-25
    for (idx, c) in (65u8..91u8).enumerate() {
        map.insert(idx as u8, c as char);
    }

    // a-z: ASCII 97-122, indices 26-51
    for (idx, c) in (97u8..123u8).enumerate() {
        map.insert((idx + 26) as u8, c as char);
    }

    // 0-9: ASCII 48-57, indices 52-61
    for (idx, c) in (48u8..58u8).enumerate() {
        map.insert((idx + 52) as u8, c as char);
    }

    // Special characters
    map.insert(62, '-');
    map.insert(63, '_');

    map
});

/// Security tiers for secret derivation
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Tiers {
    /// Low security tier
    LOW,
    /// Medium security tier
    MED,
    /// High security tier
    HIGH,
}

impl Tiers {
    /// String value for the tier
    pub const LOW: &'static str = "low";
    /// String value for the tier
    pub const MED: &'static str = "med";
    /// String value for the tier
    pub const HIGH: &'static str = "high";
}

impl From<&str> for Tiers {
    fn from(s: &str) -> Self {
        match s {
            "low" => Tiers::LOW,
            "med" => Tiers::MED,
            "high" => Tiers::HIGH,
            _ => Tiers::LOW, // Default to LOW for unrecognized values
        }
    }
}

impl Display for Tiers {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let str = match self {
            Tiers::LOW => "low",
            Tiers::MED => "med",
            Tiers::HIGH => "high",
        };
        write!(f, "{}", str)
    }
}

/// Maps Base64 character to corresponding index
#[allow(dead_code)]
pub static B64_IDX_BY_CHR: Lazy<HashMap<char, u8>> = Lazy::new(|| {
    let mut map = HashMap::new();

    // Invert the B64_CHR_BY_IDX mapping
    for (&idx, &c) in B64_CHR_BY_IDX.iter() {
        map.insert(c, idx);
    }

    map
});

#[allow(dead_code)]
pub mod cold_dex {
    use once_cell::sync::Lazy;
    use std::collections::HashMap;

    // Constants for code type values
    pub const ANB64: u8 = 0o0; // Annotated CESR B64
    pub const CTB64: u8 = 0o1; // CountCode Base64
    pub const OPB64: u8 = 0o2; // OpCode Base64
    pub const JSON: u8 = 0o3; // JSON Map Event Start
    pub const MGPK1: u8 = 0o4; // MGPK Fixed Map Event Start
    pub const CBOR: u8 = 0o5; // CBOR Map Event Start
    pub const MGPK2: u8 = 0o6; // MGPK Big 16 or 32 Map Event Start
    pub const CTOPB2: u8 = 0o7; // CountCode or OpCode Base2

    // Map of code types by value
    pub static MAP: Lazy<HashMap<&'static str, u8>> = Lazy::new(|| {
        let mut map = HashMap::new();
        map.insert("ANB64", ANB64);
        map.insert("CTB64", CTB64);
        map.insert("OPB64", OPB64);
        map.insert("JSON,", JSON);
        map.insert("MGPK1", MGPK1);
        map.insert("CBOR,", CBOR);
        map.insert("MGPK2", MGPK2);
        map.insert("CTOPB2", CTOPB2);
        map
    });

    // Tuple of code values only
    pub static TUPLE: Lazy<Vec<u8>> =
        Lazy::new(|| vec![ANB64, CTB64, OPB64, JSON, MGPK1, CBOR, MGPK2, CTOPB2]);
}

#[derive(Debug, Clone, PartialEq)]
pub struct Coldage {
    pub msg: &'static str,
    pub txt: &'static str,
    pub bny: &'static str,
    pub ano: &'static str,
}

impl Coldage {
    pub fn new(msg: &'static str, txt: &'static str, bny: &'static str, ano: &'static str) -> Self {
        Self { msg, txt, bny, ano }
    }
}

impl Default for Coldage {
    fn default() -> Self {
        Self {
            msg: "msg",
            txt: "txt",
            bny: "bny",
            ano: "ano",
        }
    }
}

impl fmt::Display for Coldage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Coldage(msg='{}', txt='{}', bny='{}', ano='{}')",
            self.msg, self.txt, self.bny, self.ano
        )
    }
}

// Define a constant similar to Colds in Python
pub const COLDS: Coldage = Coldage {
    msg: "msg",
    txt: "txt",
    bny: "bny",
    ano: "ano",
};

/// Returns status string of cold start of stream ims bytearray by looking
/// at first triplet of first byte to determine if message or counter code
/// and if counter code whether Base64 or Base2 representation
///
/// First three bits:
/// 0o0 = 000 annotated cesr
/// 0o1 = 001 cntcode B64
/// 0o2 = 010 opcode B64
/// 0o3 = 011 json
/// 0o4 = 100 mgpk
/// 0o5 = 101 cbor
/// 0o6 = 110 mgpk
/// 0o7 = 111 cntcode B2 or opcode B2
///
/// counter B64 in (0o1, 0o2) return 'txt'
/// counter B2 in (0o7)  return 'bny'
/// event in (0o3, 0o4, 0o5, 0o6)  return 'msg'
/// annotated in (0o0)  return 'ano'
pub fn sniff(ims: &[u8]) -> Result<&'static str, MatterError> {
    if ims.is_empty() {
        return Err(MatterError::ShortageError("Need more bytes.".to_string()));
    }

    // Extract the first 3 bits (tritet) by shifting right 5 bits
    let tritet = ims[0] >> 5;

    if tritet == cold_dex::JSON
        || tritet == cold_dex::MGPK1
        || tritet == cold_dex::CBOR
        || tritet == cold_dex::MGPK2
    {
        return Ok(COLDS.msg);
    }

    if tritet == cold_dex::CTB64 || tritet == cold_dex::OPB64 {
        return Ok(COLDS.txt);
    }

    if tritet == cold_dex::CTOPB2 {
        return Ok(COLDS.bny);
    }

    if tritet == cold_dex::ANB64 {
        return Ok(COLDS.ano);
    }

    Err(MatterError::ColdStartError(format!(
        "Unexpected tritet={} at stream start.",
        tritet
    )))
}

/// Various derivation codes for Matter types
#[allow(dead_code)]
pub mod mtr_dex {
    pub const ED25519_SEED: &str = "A"; // Ed25519 256 bit random seed for private key
    pub const ED25519N: &str = "B"; // Ed25519 verification key non-transferable, basic derivation
    pub const X25519: &str = "C"; // X25519 public encryption key, may be converted from Ed25519 or Ed25519N
    pub const ED25519: &str = "D"; // Ed25519 verification key basic derivation
    pub const BLAKE3_256: &str = "E"; // Blake3 256 bit digest self-addressing derivation
    pub const BLAKE2B_256: &str = "F"; // Blake2b 256 bit digest self-addressing derivation
    pub const BLAKE2S_256: &str = "G"; // Blake2s 256 bit digest self-addressing derivation
    pub const SHA3_256: &str = "H"; // SHA3 256 bit digest self-addressing derivation
    pub const SHA2_256: &str = "I"; // SHA2 256 bit digest self-addressing derivation
    pub const ECDSA_256K1_SEED: &str = "J"; // ECDSA secp256k1 256 bit random Seed for private key
    pub const ED448_SEED: &str = "K"; // Ed448 448 bit random Seed for private key
    pub const X448: &str = "L"; // X448 public encryption key, converted from Ed448
    pub const SHORT: &str = "M"; // Short 2 byte b2 number
    pub const BIG: &str = "N"; // Big 8 byte b2 number
    pub const X25519_PRIVATE: &str = "O"; // X25519 private decryption key/seed, may be converted from Ed25519
    pub const X25519_CIPHER_SEED: &str = "P"; // X25519 sealed box 124 char qb64 Cipher of 44 char qb64 Seed
    pub const ECDSA_256R1_SEED: &str = "Q"; // ECDSA secp256r1 256 bit random Seed for private key
    pub const TALL: &str = "R"; // Tall 5 byte b2 number
    pub const LARGE: &str = "S"; // Large 11 byte b2 number
    pub const GREAT: &str = "T"; // Great 14 byte b2 number
    pub const VAST: &str = "U"; // Vast 17 byte b2 number
    pub const LABEL1: &str = "V"; // Label1 1 bytes for label lead size 1
    pub const LABEL2: &str = "W"; // Label2 2 bytes for label lead size 0
    pub const TAG3: &str = "X"; // Tag3  3 B64 encoded chars for special values
    pub const TAG7: &str = "Y"; // Tag7  7 B64 encoded chars for special values
    pub const BLIND: &str = "Z"; // Blinding factor 256 bits, Cryptographic strength deterministically generated from random salt
    pub const SALT_128: &str = "0A"; // random salt/seed/nonce/private key or number of length 128 bits (Huge)
    pub const ED25519_SIG: &str = "0B"; // Ed25519 signature
    pub const ECDSA_256K1_SIG: &str = "0C"; // ECDSA secp256k1 signature
    pub const BLAKE3_512: &str = "0D"; // Blake3 512 bit digest self-addressing derivation
    pub const BLAKE2B_512: &str = "0E"; // Blake2b 512 bit digest self-addressing derivation
    pub const SHA3_512: &str = "0F"; // SHA3 512 bit digest self-addressing derivation
    pub const SHA2_512: &str = "0G"; // SHA2 512 bit digest self-addressing derivation
    pub const LONG: &str = "0H"; // Long 4 byte b2 number
    pub const ECDSA_256R1_SIG: &str = "0I"; // ECDSA secp256r1 signature
    pub const TAG1: &str = "0J"; // Tag1 1 B64 encoded char + 1 prepad for special values
    pub const TAG2: &str = "0K"; // Tag2 2 B64 encoded chars for for special values
    pub const TAG5: &str = "0L"; // Tag5 5 B64 encoded chars + 1 prepad for special values
    pub const TAG6: &str = "0M"; // Tag6 6 B64 encoded chars for special values
    pub const TAG9: &str = "0N"; // Tag9 9 B64 encoded chars + 1 prepad for special values
    pub const TAG10: &str = "0O"; // Tag10 10 B64 encoded chars for special values
    pub const GRAM_HEAD_NECK: &str = "0P"; // GramHeadNeck 32 B64 chars memogram head with neck
    pub const GRAM_HEAD: &str = "0Q"; // GramHead 28 B64 chars memogram head only
    pub const GRAM_HEAD_AID_NECK: &str = "0R"; // GramHeadAIDNeck 76 B64 chars memogram head with AID and neck
    pub const GRAM_HEAD_AID: &str = "0S"; // GramHeadAID 72 B64 chars memogram head with AID only
    pub const ECDSA_256K1N: &str = "1AAA"; // ECDSA secp256k1 verification key non-transferable, basic derivation
    pub const ECDSA_256K1: &str = "1AAB"; // ECDSA public verification or encryption key, basic derivation
    pub const ED448N: &str = "1AAC"; // Ed448 non-transferable prefix public signing verification key. Basic derivation
    pub const ED448: &str = "1AAD"; // Ed448 public signing verification key. Basic derivation
    pub const ED448_SIG: &str = "1AAE"; // Ed448 signature. Self-signing derivation
    pub const TAG4: &str = "1AAF"; // Tag4 4 B64 encoded chars for special values
    pub const DATE_TIME: &str = "1AAG"; // Base64 custom encoded 32 char ISO-8601 DateTime
    pub const X25519_CIPHER_SALT: &str = "1AAH"; // X25519 sealed box 100 char qb64 Cipher of 24 char qb64 Salt
    pub const ECDSA_256R1N: &str = "1AAI"; // ECDSA secp256r1 verification key non-transferable, basic derivation
    pub const ECDSA_256R1: &str = "1AAJ"; // ECDSA secp256r1 verification or encryption key, basic derivation
    pub const NULL: &str = "1AAK"; // Null None or empty value
    pub const NO: &str = "1AAL"; // No Falsey Boolean value
    pub const YES: &str = "1AAM"; // Yes Truthy Boolean value
    pub const TAG8: &str = "1AAN"; // Tag8 8 B64 encoded chars for special values
    pub const TBD0S: &str = "1__-"; // Testing purposes only, fixed special values with non-empty raw lead size 0
    pub const TBD0: &str = "1___"; // Testing purposes only, fixed with lead size 0
    pub const TBD1S: &str = "2__-"; // Testing purposes only, fixed special values with non-empty raw lead size 1
    pub const TBD1: &str = "2___"; // Testing purposes only, fixed with lead size 1
    pub const TBD2S: &str = "3__-"; // Testing purposes only, fixed special values with non-empty raw lead size 2
    pub const TBD2: &str = "3___"; // Testing purposes only, fixed with lead size 2
    pub const STR_B64_L0: &str = "4A"; // String Base64 only lead size 0
    pub const STR_B64_L1: &str = "5A"; // String Base64 only lead size 1
    pub const STR_B64_L2: &str = "6A"; // String Base64 only lead size 2
    pub const STR_B64_BIG_L0: &str = "7AAA"; // String Base64 only big lead size 0
    pub const STR_B64_BIG_L1: &str = "8AAA"; // String Base64 only big lead size 1
    pub const STR_B64_BIG_L2: &str = "9AAA"; // String Base64 only big lead size 2
    pub const BYTES_L0: &str = "4B"; // Byte String lead size 0
    pub const BYTES_L1: &str = "5B"; // Byte String lead size 1
    pub const BYTES_L2: &str = "6B"; // Byte String lead size 2
    pub const BYTES_BIG_L0: &str = "7AAB"; // Byte String big lead size 0
    pub const BYTES_BIG_L1: &str = "8AAB"; // Byte String big lead size 1
    pub const BYTES_BIG_L2: &str = "9AAB"; // Byte String big lead size 2
    pub const X25519_CIPHER_L0: &str = "4C"; // X25519 sealed box cipher bytes of sniffable stream plaintext lead size 0
    pub const X25519_CIPHER_L1: &str = "5C"; // X25519 sealed box cipher bytes of sniffable stream plaintext lead size 1
    pub const X25519_CIPHER_L2: &str = "6C"; // X25519 sealed box cipher bytes of sniffable stream plaintext lead size 2
    pub const X25519_CIPHER_BIG_L0: &str = "7AAC"; // X25519 sealed box cipher bytes of sniffable stream plaintext big lead size 0
    pub const X25519_CIPHER_BIG_L1: &str = "8AAC"; // X25519 sealed box cipher bytes of sniffable stream plaintext big lead size 1
    pub const X25519_CIPHER_BIG_L2: &str = "9AAC"; // X25519 sealed box cipher bytes of sniffable stream plaintext big lead size 2
    pub const X25519_CIPHER_QB64_L0: &str = "4D"; // X25519 sealed box cipher bytes of QB64 plaintext lead size 0
    pub const X25519_CIPHER_QB64_L1: &str = "5D"; // X25519 sealed box cipher bytes of QB64 plaintext lead size 1
    pub const X25519_CIPHER_QB64_L2: &str = "6D"; // X25519 sealed box cipher bytes of QB64 plaintext lead size 2
    pub const X25519_CIPHER_QB64_BIG_L0: &str = "7AAD"; // X25519 sealed box cipher bytes of QB64 plaintext big lead size 0
    pub const X25519_CIPHER_QB64_BIG_L1: &str = "8AAD"; // X25519 sealed box cipher bytes of QB64 plaintext big lead size 1
    pub const X25519_CIPHER_QB64_BIG_L2: &str = "9AAD"; // X25519 sealed box cipher bytes of QB64 plaintext big lead size 2
    pub const X25519_CIPHER_QB2_L0: &str = "4E"; // X25519 sealed box cipher bytes of QB2 plaintext lead size 0
    pub const X25519_CIPHER_QB2_L1: &str = "5E"; // X25519 sealed box cipher bytes of QB2 plaintext lead size 1
    pub const X25519_CIPHER_QB2_L2: &str = "6E"; // X25519 sealed box cipher bytes of QB2 plaintext lead size 2
    pub const X25519_CIPHER_QB2_BIG_L0: &str = "7AAE"; // X25519 sealed box cipher bytes of QB2 plaintext big lead size 0
    pub const X25519_CIPHER_QB2_BIG_L1: &str = "8AAE"; // X25519 sealed box cipher bytes of QB2 plaintext big lead size 1
    pub const X25519_CIPHER_QB2_BIG_L2: &str = "9AAE"; // X25519 sealed box cipher bytes of QB2 plaintext big lead size 2
}

// Create a HashMap from name to value
#[allow(dead_code)]
pub static MTR_DEX_MAP: Lazy<HashMap<&'static str, &'static str>> = Lazy::new(|| {
    let mut map = HashMap::new();
    map.insert("ED25519_SEED", mtr_dex::ED25519_SEED);
    map.insert("ED25519N", mtr_dex::ED25519N);
    map.insert("X25519", mtr_dex::X25519);
    map.insert("ED25519", mtr_dex::ED25519);
    map.insert("BLAKE3_256", mtr_dex::BLAKE3_256);
    map.insert("BLAKE2B_256", mtr_dex::BLAKE2B_256);
    map.insert("BLAKE2S_256", mtr_dex::BLAKE2S_256);
    map.insert("SHA3_256", mtr_dex::SHA3_256);
    map.insert("SHA2_256", mtr_dex::SHA2_256);
    map.insert("ECDSA_256K1_SEED", mtr_dex::ECDSA_256K1_SEED);
    map.insert("ED448_SEED", mtr_dex::ED448_SEED);
    map.insert("X448", mtr_dex::X448);
    map.insert("SHORT", mtr_dex::SHORT);
    map.insert("BIG", mtr_dex::BIG);
    map.insert("X25519_PRIVATE", mtr_dex::X25519_PRIVATE);
    map.insert("X25519_CIPHER_SEED", mtr_dex::X25519_CIPHER_SEED);
    map.insert("ECDSA_256R1_SEED", mtr_dex::ECDSA_256R1_SEED);
    map.insert("TALL", mtr_dex::TALL);
    map.insert("LARGE", mtr_dex::LARGE);
    map.insert("GREAT", mtr_dex::GREAT);
    map.insert("VAST", mtr_dex::VAST);
    map.insert("LABEL1", mtr_dex::LABEL1);
    map.insert("LABEL2", mtr_dex::LABEL2);
    map.insert("TAG3", mtr_dex::TAG3);
    map.insert("TAG7", mtr_dex::TAG7);
    map.insert("BLIND", mtr_dex::BLIND);
    map.insert("SALT_128", mtr_dex::SALT_128);
    map.insert("ED25519_SIG", mtr_dex::ED25519_SIG);
    map.insert("ECDSA_256K1_SIG", mtr_dex::ECDSA_256K1_SIG);
    map.insert("BLAKE3_512", mtr_dex::BLAKE3_512);
    map.insert("BLAKE2B_512", mtr_dex::BLAKE2B_512);
    map.insert("SHA3_512", mtr_dex::SHA3_512);
    map.insert("SHA2_512", mtr_dex::SHA2_512);
    map.insert("LONG", mtr_dex::LONG);
    map.insert("ECDSA_256R1_SIG", mtr_dex::ECDSA_256R1_SIG);
    map.insert("TAG1", mtr_dex::TAG1);
    map.insert("TAG2", mtr_dex::TAG2);
    map.insert("TAG5", mtr_dex::TAG5);
    map.insert("TAG6", mtr_dex::TAG6);
    map.insert("TAG9", mtr_dex::TAG9);
    map.insert("TAG10", mtr_dex::TAG10);
    map.insert("GRAM_HEAD_NECK", mtr_dex::GRAM_HEAD_NECK);
    map.insert("GRAM_HEAD", mtr_dex::GRAM_HEAD);
    map.insert("GRAM_HEAD_AID_NECK", mtr_dex::GRAM_HEAD_AID_NECK);
    map.insert("GRAM_HEAD_AID", mtr_dex::GRAM_HEAD_AID);
    map.insert("ECDSA_256K1N", mtr_dex::ECDSA_256K1N);
    map.insert("ECDSA_256K1", mtr_dex::ECDSA_256K1);
    map.insert("ED448N", mtr_dex::ED448N);
    map.insert("ED448", mtr_dex::ED448);
    map.insert("ED448_SIG", mtr_dex::ED448_SIG);
    map.insert("TAG4", mtr_dex::TAG4);
    map.insert("DATE_TIME", mtr_dex::DATE_TIME);
    map.insert("X25519_CIPHER_SALT", mtr_dex::X25519_CIPHER_SALT);
    map.insert("ECDSA_256R1N", mtr_dex::ECDSA_256R1N);
    map.insert("ECDSA_256R1", mtr_dex::ECDSA_256R1);
    map.insert("NULL", mtr_dex::NULL);
    map.insert("NO", mtr_dex::NO);
    map.insert("YES", mtr_dex::YES);
    map.insert("TAG8", mtr_dex::TAG8);
    map.insert("TBD0S", mtr_dex::TBD0S);
    map.insert("TBD0", mtr_dex::TBD0);
    map.insert("TBD1S", mtr_dex::TBD1S);
    map.insert("TBD1", mtr_dex::TBD1);
    map.insert("TBD2S", mtr_dex::TBD2S);
    map.insert("TBD2", mtr_dex::TBD2);
    map.insert("STR_B64_L0", mtr_dex::STR_B64_L0);
    map.insert("STR_B64_L1", mtr_dex::STR_B64_L1);
    map.insert("STR_B64_L2", mtr_dex::STR_B64_L2);
    map.insert("STR_B64_BIG_L0", mtr_dex::STR_B64_BIG_L0);
    map.insert("STR_B64_BIG_L1", mtr_dex::STR_B64_BIG_L1);
    map.insert("STR_B64_BIG_L2", mtr_dex::STR_B64_BIG_L2);
    map.insert("BYTES_L0", mtr_dex::BYTES_L0);
    map.insert("BYTES_L1", mtr_dex::BYTES_L1);
    map.insert("BYTES_L2", mtr_dex::BYTES_L2);
    map.insert("BYTES_BIG_L0", mtr_dex::BYTES_BIG_L0);
    map.insert("BYTES_BIG_L1", mtr_dex::BYTES_BIG_L1);
    map.insert("BYTES_BIG_L2", mtr_dex::BYTES_BIG_L2);
    map.insert("X25519_CIPHER_L0", mtr_dex::X25519_CIPHER_L0);
    map.insert("X25519_CIPHER_L1", mtr_dex::X25519_CIPHER_L1);
    map.insert("X25519_CIPHER_L2", mtr_dex::X25519_CIPHER_L2);
    map.insert("X25519_CIPHER_BIG_L0", mtr_dex::X25519_CIPHER_BIG_L0);
    map.insert("X25519_CIPHER_BIG_L1", mtr_dex::X25519_CIPHER_BIG_L1);
    map.insert("X25519_CIPHER_BIG_L2", mtr_dex::X25519_CIPHER_BIG_L2);
    map.insert("X25519_CIPHER_QB64_L0", mtr_dex::X25519_CIPHER_QB64_L0);
    map.insert("X25519_CIPHER_QB64_L1", mtr_dex::X25519_CIPHER_QB64_L1);
    map.insert("X25519_CIPHER_QB64_L2", mtr_dex::X25519_CIPHER_QB64_L2);
    map.insert(
        "X25519_CIPHER_QB64_BIG_L0",
        mtr_dex::X25519_CIPHER_QB64_BIG_L0,
    );
    map.insert(
        "X25519_CIPHER_QB64_BIG_L1",
        mtr_dex::X25519_CIPHER_QB64_BIG_L1,
    );
    map.insert(
        "X25519_CIPHER_QB64_BIG_L2",
        mtr_dex::X25519_CIPHER_QB64_BIG_L2,
    );
    map.insert("X25519_CIPHER_QB2_L0", mtr_dex::X25519_CIPHER_QB2_L0);
    map.insert("X25519_CIPHER_QB2_L1", mtr_dex::X25519_CIPHER_QB2_L1);
    map.insert("X25519_CIPHER_QB2_L2", mtr_dex::X25519_CIPHER_QB2_L2);
    map.insert(
        "X25519_CIPHER_QB2_BIG_L0",
        mtr_dex::X25519_CIPHER_QB2_BIG_L0,
    );
    map.insert(
        "X25519_CIPHER_QB2_BIG_L1",
        mtr_dex::X25519_CIPHER_QB2_BIG_L1,
    );
    map.insert(
        "X25519_CIPHER_QB2_BIG_L2",
        mtr_dex::X25519_CIPHER_QB2_BIG_L2,
    );
    map
});

#[allow(dead_code)]
pub mod small_vrz_dex {
    use once_cell::sync::Lazy;
    use std::collections::HashMap;

    pub const LEAD0: &str = "4"; // First Selector Character for all ls == 0 codes
    pub const LEAD1: &str = "5"; // First Selector Character for all ls == 1 codes
    pub const LEAD2: &str = "6"; // First Selector Character for all ls == 2 codes

    // Create a HashMap from name to value
    pub static MAP: Lazy<HashMap<&'static str, &'static str>> = Lazy::new(|| {
        let mut map = HashMap::new();
        map.insert("LEAD0", LEAD0);
        map.insert("LEAD1", LEAD1);
        map.insert("LEAD2", LEAD2);
        map
    });

    pub static TUPLE: [&'static str; 3] = [LEAD0, LEAD1, LEAD2];
}

#[allow(dead_code)]
pub mod large_vrz_dex {
    use once_cell::sync::Lazy;
    use std::collections::HashMap;

    pub const LEAD0_BIG: &str = "7"; // First Selector Character for all ls == 0 codes
    pub const LEAD1_BIG: &str = "8"; // First Selector Character for all ls == 1 codes
    pub const LEAD2_BIG: &str = "9"; // First Selector Character for all ls == 2 codes

    // Create a HashMap from name to value for large_vrz_dex
    pub static MAP: Lazy<HashMap<&'static str, &'static str>> = Lazy::new(|| {
        let mut map = HashMap::new();
        map.insert("LEAD0_BIG", LEAD0_BIG);
        map.insert("LEAD1_BIG", LEAD1_BIG);
        map.insert("LEAD2_BIG", LEAD2_BIG);
        map
    });

    pub static TUPLE: [&'static str; 3] = [LEAD0_BIG, LEAD1_BIG, LEAD2_BIG];
}

/// BextCodex is codex of all variable sized Base64 Text (Bext) derivation codes.
/// Only provides defined codes.
/// Undefined are left out so that inclusion(exclusion) via contains works.
#[allow(dead_code)]
pub mod bex_dex {
    /// String Base64 Only Leader Size 0
    pub const STR_B64_L0: &str = "4A";

    /// String Base64 Only Leader Size 1
    pub const STR_B64_L1: &str = "5A";

    /// String Base64 Only Leader Size 2
    pub const STR_B64_L2: &str = "6A";

    /// String Base64 Only Big Leader Size 0
    pub const STR_B64_BIG_L0: &str = "7AAA";

    /// String Base64 Only Big Leader Size 1
    pub const STR_B64_BIG_L1: &str = "8AAA";

    /// String Base64 Only Big Leader Size 2
    pub const STR_B64_BIG_L2: &str = "9AAA";

    /// Map of code to size of code (in characters) in Base64
    pub const MAP: once_cell::sync::Lazy<std::collections::HashMap<&'static str, usize>> =
        once_cell::sync::Lazy::new(|| {
            let mut map = std::collections::HashMap::new();
            map.insert(STR_B64_L0, 2);
            map.insert(STR_B64_L1, 2);
            map.insert(STR_B64_L2, 2);
            map.insert(STR_B64_BIG_L0, 4);
            map.insert(STR_B64_BIG_L1, 4);
            map.insert(STR_B64_BIG_L2, 4);
            map
        });

    /// Tuple of string constants in order of definition
    pub const TUPLE: &[&str] = &[
        STR_B64_L0,
        STR_B64_L1,
        STR_B64_L2,
        STR_B64_BIG_L0,
        STR_B64_BIG_L1,
        STR_B64_BIG_L2,
    ];
}

/// TextCodex is codex of all variable sized byte string (Text) derivation codes.
/// Only provides defined codes.
/// Undefined are left out so that inclusion(exclusion) via contains works.
#[allow(dead_code)]
pub mod tex_dex {
    /// Byte String lead size 0
    pub const BYTES_L0: &str = "4B";

    /// Byte String lead size 1
    pub const BYTES_L1: &str = "5B";

    /// Byte String lead size 2
    pub const BYTES_L2: &str = "6B";

    /// Byte String big lead size 0
    pub const BYTES_BIG_L0: &str = "7AAB";

    /// Byte String big lead size 1
    pub const BYTES_BIG_L1: &str = "8AAB";

    /// Byte String big lead size 2
    pub const BYTES_BIG_L2: &str = "9AAB";

    /// Map of code to size of code (in characters) in Base64
    pub const MAP: once_cell::sync::Lazy<std::collections::HashMap<&'static str, usize>> =
        once_cell::sync::Lazy::new(|| {
            let mut map = std::collections::HashMap::new();
            map.insert(BYTES_L0, 2);
            map.insert(BYTES_L1, 2);
            map.insert(BYTES_L2, 2);
            map.insert(BYTES_BIG_L0, 4);
            map.insert(BYTES_BIG_L1, 4);
            map.insert(BYTES_BIG_L2, 4);
            map
        });

    /// Tuple of string constants in order of definition
    pub const TUPLE: &[&str] = &[
        BYTES_L0,
        BYTES_L1,
        BYTES_L2,
        BYTES_BIG_L0,
        BYTES_BIG_L1,
        BYTES_BIG_L2,
    ];
}

/// DigCodex is codex of all digest derivation codes. This is needed to ensure
/// delegated inception using a self-addressing derivation i.e. digest derivation
/// code.
/// Only provides defined codes.
/// Undefined are left out so that inclusion(exclusion) via contains works.
#[allow(dead_code)]
pub mod dig_dex {
    use once_cell::sync::Lazy;
    use std::collections::HashMap;

    /// Blake3 256 bit digest self-addressing derivation
    pub const BLAKE3_256: &str = "E";

    /// Blake2b 256 bit digest self-addressing derivation
    pub const BLAKE2B_256: &str = "F";

    /// Blake2s 256 bit digest self-addressing derivation
    pub const BLAKE2S_256: &str = "G";

    /// SHA3 256 bit digest self-addressing derivation
    pub const SHA3_256: &str = "H";

    /// SHA2 256 bit digest self-addressing derivation
    pub const SHA2_256: &str = "I";

    /// Blake3 512 bit digest self-addressing derivation
    pub const BLAKE3_512: &str = "0D";

    /// Blake2b 512 bit digest self-addressing derivation
    pub const BLAKE2B_512: &str = "0E";

    /// SHA3 512 bit digest self-addressing derivation
    pub const SHA3_512: &str = "0F";

    /// SHA2 512 bit digest self-addressing derivation
    pub const SHA2_512: &str = "0G";

    #[allow(dead_code)]
    pub static MAP: Lazy<HashMap<&'static str, &'static str>> = Lazy::new(|| {
        let mut map = HashMap::new();
        map.insert("BLAKE3_256", BLAKE3_256);
        map.insert("BLAKE2B_256", BLAKE2B_256);
        map.insert("BLAKE2S_256", BLAKE2S_256);
        map.insert("SHA3_256", SHA3_256);
        map.insert("SHA2_256", SHA2_256);
        map.insert("BLAKE3_512", BLAKE3_512);
        map.insert("BLAKE2B_512", BLAKE2B_512);
        map.insert("SHA3_512", SHA3_512);
        map.insert("SHA2_512", SHA2_512);
        map
    });

    pub static TUPLE: [&'static str; 9] = [
        BLAKE3_256,
        BLAKE2B_256,
        BLAKE2S_256,
        SHA3_256,
        SHA2_256,
        BLAKE3_512,
        BLAKE2B_512,
        SHA3_512,
        SHA2_512,
    ];
}

/// NumCodex is codex of Base64 derivation codes for compactly representing
/// numbers across a wide rage of sizes.
///
/// Only provides defined codes.
/// Undefined are left out so that inclusion(exclusion) via contains works.
#[allow(dead_code)]
pub mod num_dex {
    use once_cell::sync::Lazy;
    use std::collections::HashMap;

    /// Short 2 byte b2 number
    pub const SHORT: &str = "M";

    /// Long 4 byte b2 number
    pub const LONG: &str = "0H";

    /// Tall 5 byte b2 number
    pub const TALL: &str = "R";

    /// Big 8 byte b2 number
    pub const BIG: &str = "N";

    /// Large 11 byte b2 number
    pub const LARGE: &str = "S";

    /// Great 14 byte b2 number
    pub const GREAT: &str = "T";

    /// Huge 16 byte b2 number (same as Salt_128)
    pub const HUGE: &str = "0A";

    /// Vast 17 byte b2 number
    pub const VAST: &str = "U";

    pub static MAP: Lazy<HashMap<&'static str, &'static str>> = Lazy::new(|| {
        let mut map = HashMap::new();
        map.insert("SHORT", SHORT);
        map.insert("LONG", LONG);
        map.insert("TALL", TALL);
        map.insert("BIG", BIG);
        map.insert("LARGE", LARGE);
        map.insert("GREAT", GREAT);
        map.insert("HUGE", HUGE);
        map.insert("VAST", VAST);
        map
    });

    pub static TUPLE: [&'static str; 8] = [SHORT, LONG, TALL, BIG, LARGE, GREAT, HUGE, VAST];
}

/// TagCodex is codex of Base64 derivation codes for compactly representing
/// various small Base64 tag values as special code soft part values.
///
/// Only provides defined codes.
/// Undefined are left out so that inclusion(exclusion) via contains works.
#[allow(dead_code)]
pub mod tag_dex {
    use once_cell::sync::Lazy;
    use std::collections::HashMap;

    /// 1 B64 char tag with 1 pre pad
    pub const TAG1: &str = "0J";

    /// 2 B64 char tag
    pub const TAG2: &str = "0K";

    /// 3 B64 char tag
    pub const TAG3: &str = "X";

    /// 4 B64 char tag
    pub const TAG4: &str = "1AAF";

    /// 5 B64 char tag with 1 pre pad
    pub const TAG5: &str = "0L";

    /// 6 B64 char tag
    pub const TAG6: &str = "0M";

    /// 7 B64 char tag
    pub const TAG7: &str = "Y";

    /// 8 B64 char tag
    pub const TAG8: &str = "1AAN";

    /// 9 B64 char tag with 1 pre pad
    pub const TAG9: &str = "0N";

    /// 10 B64 char tag
    pub const TAG10: &str = "0O";

    pub static MAP: Lazy<HashMap<&'static str, &'static str>> = Lazy::new(|| {
        let mut map = HashMap::new();
        map.insert("TAG1", TAG1);
        map.insert("TAG2", TAG2);
        map.insert("TAG3", TAG3);
        map.insert("TAG4", TAG4);
        map.insert("TAG5", TAG5);
        map.insert("TAG6", TAG6);
        map.insert("TAG7", TAG7);
        map.insert("TAG8", TAG8);
        map.insert("TAG9", TAG9);
        map.insert("TAG10", TAG10);
        map
    });
}

/// LabelCodex is codex of.
///
/// Only provides defined codes.
/// Undefined are left out so that inclusion(exclusion) via contains works.
#[allow(dead_code)]
pub mod label_dex {
    use once_cell::sync::Lazy;
    use std::collections::HashMap;

    /// 1 B64 char tag with 1 pre pad
    pub const TAG1: &str = "0J";

    /// 2 B64 char tag
    pub const TAG2: &str = "0K";

    /// 3 B64 char tag
    pub const TAG3: &str = "X";

    /// 4 B64 char tag
    pub const TAG4: &str = "1AAF";

    /// 5 B64 char tag with 1 pre pad
    pub const TAG5: &str = "0L";

    /// 6 B64 char tag
    pub const TAG6: &str = "0M";

    /// 7 B64 char tag
    pub const TAG7: &str = "Y";

    /// 8 B64 char tag
    pub const TAG8: &str = "1AAN";

    /// 9 B64 char tag with 1 pre pad
    pub const TAG9: &str = "0N";

    /// 10 B64 char tag
    pub const TAG10: &str = "0O";

    /// String Base64 Only Leader Size 0
    pub const STRB64_L0: &str = "4A";

    /// String Base64 Only Leader Size 1
    pub const STRB64_L1: &str = "5A";

    /// String Base64 Only Leader Size 2
    pub const STRB64_L2: &str = "6A";

    /// String Base64 Only Big Leader Size 0
    pub const STRB64_BIG_L0: &str = "7AAA";

    /// String Base64 Only Big Leader Size 1
    pub const STRB64_BIG_L1: &str = "8AAA";

    /// String Base64 Only Big Leader Size 2
    pub const STRB64_BIG_L2: &str = "9AAA";

    /// Label1 1 bytes for label lead size 1
    pub const LABEL1: &str = "V";

    /// Label2 2 bytes for label lead size 0
    pub const LABEL2: &str = "W";

    /// Byte String lead size 0
    pub const BYTES_L0: &str = "4B";

    /// Byte String lead size 1
    pub const BYTES_L1: &str = "5B";

    /// Byte String lead size 2
    pub const BYTES_L2: &str = "6B";

    /// Byte String big lead size 0
    pub const BYTES_BIG_L0: &str = "7AAB";

    /// Byte String big lead size 1
    pub const BYTES_BIG_L1: &str = "8AAB";

    /// Byte String big lead size 2
    pub const BYTES_BIG_L2: &str = "9AAB";

    pub static MAP: Lazy<HashMap<&'static str, &'static str>> = Lazy::new(|| {
        let mut map = HashMap::new();
        map.insert("TAG1", TAG1);
        map.insert("TAG2", TAG2);
        map.insert("TAG3", TAG3);
        map.insert("TAG4", TAG4);
        map.insert("TAG5", TAG5);
        map.insert("TAG6", TAG6);
        map.insert("TAG7", TAG7);
        map.insert("TAG8", TAG8);
        map.insert("TAG9", TAG9);
        map.insert("TAG10", TAG10);
        map.insert("STRB64_L0", STRB64_L0);
        map.insert("STRB64_L1", STRB64_L1);
        map.insert("STRB64_L2", STRB64_L2);
        map.insert("STRB64_BIG_L0", STRB64_BIG_L0);
        map.insert("STRB64_BIG_L1", STRB64_BIG_L1);
        map.insert("STRB64_BIG_L2", STRB64_BIG_L2);
        map.insert("LABEL1", LABEL1);
        map.insert("LABEL2", LABEL2);
        map.insert("BYTES_L0", BYTES_L0);
        map.insert("BYTES_L1", BYTES_L1);
        map.insert("BYTES_L2", BYTES_L2);
        map.insert("BYTES_BIG_L0", BYTES_BIG_L0);
        map.insert("BYTES_BIG_L1", BYTES_BIG_L1);
        map.insert("BYTES_BIG_L2", BYTES_BIG_L2);
        map
    });
}

/// PreCodex is codex of all identifier prefix derivation codes.
/// This is needed to verify valid inception events.
/// Only provides defined codes.
/// Undefined are left out so that inclusion(exclusion) via contains works.
#[allow(dead_code)]
pub mod pre_dex {
    use once_cell::sync::Lazy;
    use std::collections::HashMap;

    /// Ed25519 verification key non-transferable, basic derivation
    pub const ED25519N: &str = "B";

    /// Ed25519 verification key, basic derivation
    pub const ED25519: &str = "D";

    /// Blake3 256 bit digest self-addressing derivation
    pub const BLAKE3_256: &str = "E";

    /// Blake2b 256 bit digest self-addressing derivation
    pub const BLAKE2B_256: &str = "F";

    /// Blake2s 256 bit digest self-addressing derivation
    pub const BLAKE2S_256: &str = "G";

    /// SHA3 256 bit digest self-addressing derivation
    pub const SHA3_256: &str = "H";

    /// SHA2 256 bit digest self-addressing derivation
    pub const SHA2_256: &str = "I";

    /// Blake3 512 bit digest self-addressing derivation
    pub const BLAKE3_512: &str = "0D";

    /// Blake2b 512 bit digest self-addressing derivation
    pub const BLAKE2B_512: &str = "0E";

    /// SHA3 512 bit digest self-addressing derivation
    pub const SHA3_512: &str = "0F";

    /// SHA2 512 bit digest self-addressing derivation
    pub const SHA2_512: &str = "0G";

    /// ECDSA secp256k1 verification key non-transferable, basic derivation
    pub const ECDSA_256K1N: &str = "1AAA";

    /// ECDSA public verification or encryption key, basic derivation
    pub const ECDSA_256K1: &str = "1AAB";

    /// Ed448 verification key non-transferable, basic derivation
    pub const ED448N: &str = "1AAC";

    /// Ed448 verification key, basic derivation
    pub const ED448: &str = "1AAD";

    /// Ed448 signature. Self-signing derivation
    pub const ED448_SIG: &str = "1AAE";

    /// ECDSA secp256r1 verification key non-transferable, basic derivation
    pub const ECDSA_256R1N: &str = "1AAI";

    /// ECDSA secp256r1 verification or encryption key, basic derivation
    pub const ECDSA_256R1: &str = "1AAJ";

    pub static MAP: Lazy<HashMap<&'static str, &'static str>> = Lazy::new(|| {
        let mut map = HashMap::new();
        map.insert("ED25519N", ED25519N);
        map.insert("ED25519", ED25519);
        map.insert("BLAKE3_256", BLAKE3_256);
        map.insert("BLAKE2B_256", BLAKE2B_256);
        map.insert("BLAKE2S_256", BLAKE2S_256);
        map.insert("SHA3_256", SHA3_256);
        map.insert("SHA2_256", SHA2_256);
        map.insert("BLAKE3_512", BLAKE3_512);
        map.insert("BLAKE2B_512", BLAKE2B_512);
        map.insert("SHA3_512", SHA3_512);
        map.insert("SHA2_512", SHA2_512);
        map.insert("ECDSA_256K1N", ECDSA_256K1N);
        map.insert("ECDSA_256K1", ECDSA_256K1);
        map.insert("ED448N", ED448N);
        map.insert("ED448", ED448);
        map.insert("ED448_SIG", ED448_SIG);
        map.insert("ECDSA_256R1N", ECDSA_256R1N);
        map.insert("ECDSA_256R1", ECDSA_256R1);
        map
    });

    pub static TUPLE: [&'static str; 18] = [
        ED25519N,
        ED25519,
        BLAKE3_256,
        BLAKE2B_256,
        BLAKE2S_256,
        SHA3_256,
        SHA2_256,
        BLAKE3_512,
        BLAKE2B_512,
        SHA3_512,
        SHA2_512,
        ECDSA_256K1N,
        ECDSA_256K1,
        ED448N,
        ED448,
        ED448_SIG,
        ECDSA_256R1N,
        ECDSA_256R1,
    ];
}

/// NonTransCodex is codex of all non-transferable derivation codes
/// Only provides defined codes.
/// Undefined are left out so that inclusion(exclusion) via contains works.
#[allow(dead_code)]
pub mod non_trans_dex {
    use once_cell::sync::Lazy;
    use std::collections::HashMap;

    /// Ed25519 verification key non-transferable, basic derivation
    pub const ED25519N: &str = "B";

    /// ECDSA secp256k1 verification key non-transferable, basic derivation
    pub const ECDSA_256K1N: &str = "1AAA";

    /// Ed448 verification key non-transferable, basic derivation
    pub const ED448N: &str = "1AAC";

    /// ECDSA secp256r1 verification key non-transferable, basic derivation
    pub const ECDSA_256R1N: &str = "1AAI";

    pub static MAP: Lazy<HashMap<&'static str, &'static str>> = Lazy::new(|| {
        let mut map = HashMap::new();
        map.insert("ED25519N", ED25519N);
        map.insert("ECDSA_256K1N", ECDSA_256K1N);
        map.insert("ED448N", ED448N);
        map.insert("ECDSA_256R1N", ECDSA_256R1N);
        map
    });

    pub static TUPLE: [&'static str; 4] = [ED25519N, ECDSA_256K1N, ED448N, ECDSA_256R1N];
}

/// PreNonDigCodex is codex of all prefixive but non-digestive derivation codes
/// Only provides defined codes.
/// Undefined are left out so that inclusion(exclusion) via contains works.
#[allow(dead_code)]
pub mod pre_non_dig_dex {
    use once_cell::sync::Lazy;
    use std::collections::HashMap;

    /// Ed25519 verification key non-transferable, basic derivation
    pub const ED25519N: &str = "B";

    /// Ed25519 verification key, basic derivation
    pub const ED25519: &str = "D";

    /// ECDSA secp256k1 verification key non-transferable, basic derivation
    pub const ECDSA_256K1N: &str = "1AAA";

    /// ECDSA public verification or encryption key, basic derivation
    pub const ECDSA_256K1: &str = "1AAB";

    /// Ed448 verification key non-transferable, basic derivation
    pub const ED448N: &str = "1AAC";

    /// Ed448 verification key, basic derivation
    pub const ED448: &str = "1AAD";

    /// ECDSA secp256r1 verification key non-transferable, basic derivation
    pub const ECDSA_256R1N: &str = "1AAI";

    /// ECDSA secp256r1 verification or encryption key, basic derivation
    pub const ECDSA_256R1: &str = "1AAJ";

    pub static MAP: Lazy<HashMap<&'static str, &'static str>> = Lazy::new(|| {
        let mut map = HashMap::new();
        map.insert("ED25519N", ED25519N);
        map.insert("ED25519", ED25519);
        map.insert("ECDSA_256K1N", ECDSA_256K1N);
        map.insert("ECDSA_256K1", ECDSA_256K1);
        map.insert("ED448N", ED448N);
        map.insert("ED448", ED448);
        map.insert("ECDSA_256R1N", ECDSA_256R1N);
        map.insert("ECDSA_256R1", ECDSA_256R1);
        map
    });
}

#[derive(Clone, Copy, Debug)]
pub struct Sizage {
    pub hs: u32,         // header size
    pub ss: u32,         // section size
    pub xs: u32,         // extra size
    pub fs: Option<u32>, // field size
    pub ls: u32,         // list size
}

pub fn get_sizes() -> HashMap<&'static str, Sizage> {
    let mut sizes = HashMap::new();

    // Adding all the size entries
    sizes.insert(
        "A",
        Sizage {
            hs: 1,
            ss: 0,
            xs: 0,
            fs: Some(44),
            ls: 0,
        },
    ); // Ed25519_Seed
    sizes.insert(
        "B",
        Sizage {
            hs: 1,
            ss: 0,
            xs: 0,
            fs: Some(44),
            ls: 0,
        },
    ); // Ed25519N
    sizes.insert(
        "C",
        Sizage {
            hs: 1,
            ss: 0,
            xs: 0,
            fs: Some(44),
            ls: 0,
        },
    ); // X25519
    sizes.insert(
        "D",
        Sizage {
            hs: 1,
            ss: 0,
            xs: 0,
            fs: Some(44),
            ls: 0,
        },
    ); // Ed25519
    sizes.insert(
        "E",
        Sizage {
            hs: 1,
            ss: 0,
            xs: 0,
            fs: Some(44),
            ls: 0,
        },
    ); // Blake3_256
    sizes.insert(
        "F",
        Sizage {
            hs: 1,
            ss: 0,
            xs: 0,
            fs: Some(44),
            ls: 0,
        },
    ); // Blake2b_256
    sizes.insert(
        "G",
        Sizage {
            hs: 1,
            ss: 0,
            xs: 0,
            fs: Some(44),
            ls: 0,
        },
    ); // Blake2s_256
    sizes.insert(
        "H",
        Sizage {
            hs: 1,
            ss: 0,
            xs: 0,
            fs: Some(44),
            ls: 0,
        },
    ); // SHA3_256
    sizes.insert(
        "I",
        Sizage {
            hs: 1,
            ss: 0,
            xs: 0,
            fs: Some(44),
            ls: 0,
        },
    ); // SHA2_256
    sizes.insert(
        "J",
        Sizage {
            hs: 1,
            ss: 0,
            xs: 0,
            fs: Some(44),
            ls: 0,
        },
    ); // ECDSA_256k1N
    sizes.insert(
        "K",
        Sizage {
            hs: 1,
            ss: 0,
            xs: 0,
            fs: Some(76),
            ls: 0,
        },
    ); // ECDSA_256r1N
    sizes.insert(
        "L",
        Sizage {
            hs: 1,
            ss: 0,
            xs: 0,
            fs: Some(76),
            ls: 0,
        },
    ); // X448
    sizes.insert(
        "M",
        Sizage {
            hs: 1,
            ss: 0,
            xs: 0,
            fs: Some(4),
            ls: 0,
        },
    ); // SHA3_512
    sizes.insert(
        "N",
        Sizage {
            hs: 1,
            ss: 0,
            xs: 0,
            fs: Some(12),
            ls: 0,
        },
    ); // SHA2_512
    sizes.insert(
        "O",
        Sizage {
            hs: 1,
            ss: 0,
            xs: 0,
            fs: Some(44),
            ls: 0,
        },
    ); // ECDSA_256k1
    sizes.insert(
        "P",
        Sizage {
            hs: 1,
            ss: 0,
            xs: 0,
            fs: Some(124),
            ls: 0,
        },
    ); // ECDSA_256r1
    sizes.insert(
        "Q",
        Sizage {
            hs: 1,
            ss: 0,
            xs: 0,
            fs: Some(44),
            ls: 0,
        },
    ); // Ed448N
    sizes.insert(
        "R",
        Sizage {
            hs: 1,
            ss: 0,
            xs: 0,
            fs: Some(8),
            ls: 0,
        },
    ); // Ed448
    sizes.insert(
        "S",
        Sizage {
            hs: 1,
            ss: 0,
            xs: 0,
            fs: Some(16),
            ls: 0,
        },
    ); // Ed448_Sig
    sizes.insert(
        "U",
        Sizage {
            hs: 1,
            ss: 0,
            xs: 0,
            fs: Some(20),
            ls: 0,
        },
    ); // Blake3_512
    sizes.insert(
        "V",
        Sizage {
            hs: 1,
            ss: 0,
            xs: 0,
            fs: Some(24),
            ls: 0,
        },
    ); // Blake2b_512
    sizes.insert(
        "W",
        Sizage {
            hs: 1,
            ss: 0,
            xs: 0,
            fs: Some(4),
            ls: 0,
        },
    ); // ECDSA_256k1_Sig
    sizes.insert(
        "X",
        Sizage {
            hs: 1,
            ss: 3,
            xs: 0,
            fs: Some(4),
            ls: 0,
        },
    ); // ECDSA_256r1_Sig
    sizes.insert(
        "Y",
        Sizage {
            hs: 1,
            ss: 7,
            xs: 0,
            fs: Some(4),
            ls: 0,
        },
    ); // ECDSA_256k1_Seed
    sizes.insert(
        "Z",
        Sizage {
            hs: 1,
            ss: 0,
            xs: 0,
            fs: Some(8),
            ls: 0,
        },
    ); // ECDSA_256r1_Seed
    sizes.insert(
        "0A",
        Sizage {
            hs: 2,
            ss: 0,
            xs: 0,
            fs: Some(24),
            ls: 0,
        },
    );
    sizes.insert(
        "0B",
        Sizage {
            hs: 2,
            ss: 0,
            xs: 0,
            fs: Some(88),
            ls: 0,
        },
    );
    sizes.insert(
        "0C",
        Sizage {
            hs: 2,
            ss: 0,
            xs: 0,
            fs: Some(88),
            ls: 0,
        },
    );
    sizes.insert(
        "0D",
        Sizage {
            hs: 2,
            ss: 0,
            xs: 0,
            fs: Some(88),
            ls: 0,
        },
    );
    sizes.insert(
        "0E",
        Sizage {
            hs: 2,
            ss: 0,
            xs: 0,
            fs: Some(88),
            ls: 0,
        },
    );
    sizes.insert(
        "0F",
        Sizage {
            hs: 2,
            ss: 0,
            xs: 0,
            fs: Some(88),
            ls: 0,
        },
    );
    sizes.insert(
        "0G",
        Sizage {
            hs: 2,
            ss: 0,
            xs: 0,
            fs: Some(88),
            ls: 0,
        },
    );
    sizes.insert(
        "0H",
        Sizage {
            hs: 2,
            ss: 0,
            xs: 0,
            fs: Some(8),
            ls: 0,
        },
    );
    sizes.insert(
        "0I",
        Sizage {
            hs: 2,
            ss: 0,
            xs: 0,
            fs: Some(88),
            ls: 0,
        },
    );
    sizes.insert(
        "0J",
        Sizage {
            hs: 2,
            ss: 2,
            xs: 1,
            fs: Some(4),
            ls: 0,
        },
    );
    sizes.insert(
        "0K",
        Sizage {
            hs: 2,
            ss: 2,
            xs: 0,
            fs: Some(4),
            ls: 0,
        },
    );
    sizes.insert(
        "0L",
        Sizage {
            hs: 2,
            ss: 6,
            xs: 1,
            fs: Some(8),
            ls: 0,
        },
    );
    sizes.insert(
        "0M",
        Sizage {
            hs: 2,
            ss: 6,
            xs: 0,
            fs: Some(8),
            ls: 0,
        },
    );
    sizes.insert(
        "0N",
        Sizage {
            hs: 2,
            ss: 10,
            xs: 1,
            fs: Some(12),
            ls: 0,
        },
    );
    sizes.insert(
        "0O",
        Sizage {
            hs: 2,
            ss: 10,
            xs: 0,
            fs: Some(12),
            ls: 0,
        },
    );
    sizes.insert(
        "0P",
        Sizage {
            hs: 2,
            ss: 22,
            xs: 0,
            fs: Some(32),
            ls: 0,
        },
    );
    sizes.insert(
        "0Q",
        Sizage {
            hs: 2,
            ss: 22,
            xs: 0,
            fs: Some(28),
            ls: 0,
        },
    );
    sizes.insert(
        "0R",
        Sizage {
            hs: 2,
            ss: 22,
            xs: 0,
            fs: Some(76),
            ls: 0,
        },
    );
    sizes.insert(
        "0S",
        Sizage {
            hs: 2,
            ss: 22,
            xs: 0,
            fs: Some(72),
            ls: 0,
        },
    );

    sizes.insert(
        "1AAA",
        Sizage {
            hs: 4,
            ss: 0,
            xs: 0,
            fs: Some(48),
            ls: 0,
        },
    );
    sizes.insert(
        "1AAB",
        Sizage {
            hs: 4,
            ss: 0,
            xs: 0,
            fs: Some(48),
            ls: 0,
        },
    );
    sizes.insert(
        "1AAC",
        Sizage {
            hs: 4,
            ss: 0,
            xs: 0,
            fs: Some(80),
            ls: 0,
        },
    );
    sizes.insert(
        "1AAD",
        Sizage {
            hs: 4,
            ss: 0,
            xs: 0,
            fs: Some(80),
            ls: 0,
        },
    );
    sizes.insert(
        "1AAE",
        Sizage {
            hs: 4,
            ss: 0,
            xs: 0,
            fs: Some(156),
            ls: 0,
        },
    );
    sizes.insert(
        "1AAF",
        Sizage {
            hs: 4,
            ss: 4,
            xs: 0,
            fs: Some(8),
            ls: 0,
        },
    );
    sizes.insert(
        "1AAG",
        Sizage {
            hs: 4,
            ss: 0,
            xs: 0,
            fs: Some(36),
            ls: 0,
        },
    );
    sizes.insert(
        "1AAH",
        Sizage {
            hs: 4,
            ss: 0,
            xs: 0,
            fs: Some(100),
            ls: 0,
        },
    );
    sizes.insert(
        "1AAI",
        Sizage {
            hs: 4,
            ss: 0,
            xs: 0,
            fs: Some(48),
            ls: 0,
        },
    );
    sizes.insert(
        "1AAJ",
        Sizage {
            hs: 4,
            ss: 0,
            xs: 0,
            fs: Some(48),
            ls: 0,
        },
    );
    sizes.insert(
        "1AAK",
        Sizage {
            hs: 4,
            ss: 0,
            xs: 0,
            fs: Some(4),
            ls: 0,
        },
    );
    sizes.insert(
        "1AAL",
        Sizage {
            hs: 4,
            ss: 0,
            xs: 0,
            fs: Some(4),
            ls: 0,
        },
    );
    sizes.insert(
        "1AAM",
        Sizage {
            hs: 4,
            ss: 0,
            xs: 0,
            fs: Some(4),
            ls: 0,
        },
    );
    sizes.insert(
        "1AAN",
        Sizage {
            hs: 4,
            ss: 8,
            xs: 0,
            fs: Some(12),
            ls: 0,
        },
    );

    sizes.insert(
        "1__-",
        Sizage {
            hs: 4,
            ss: 2,
            xs: 0,
            fs: Some(12),
            ls: 0,
        },
    );
    sizes.insert(
        "1___",
        Sizage {
            hs: 4,
            ss: 0,
            xs: 0,
            fs: Some(8),
            ls: 0,
        },
    );
    sizes.insert(
        "2__-",
        Sizage {
            hs: 4,
            ss: 2,
            xs: 1,
            fs: Some(12),
            ls: 1,
        },
    );
    sizes.insert(
        "2___",
        Sizage {
            hs: 4,
            ss: 0,
            xs: 0,
            fs: Some(8),
            ls: 1,
        },
    );
    sizes.insert(
        "3__-",
        Sizage {
            hs: 4,
            ss: 2,
            xs: 0,
            fs: Some(12),
            ls: 2,
        },
    );
    sizes.insert(
        "3___",
        Sizage {
            hs: 4,
            ss: 0,
            xs: 0,
            fs: Some(8),
            ls: 2,
        },
    );

    sizes.insert(
        "4A",
        Sizage {
            hs: 2,
            ss: 2,
            xs: 0,
            fs: None,
            ls: 0,
        },
    );
    sizes.insert(
        "5A",
        Sizage {
            hs: 2,
            ss: 2,
            xs: 0,
            fs: None,
            ls: 1,
        },
    );
    sizes.insert(
        "6A",
        Sizage {
            hs: 2,
            ss: 2,
            xs: 0,
            fs: None,
            ls: 2,
        },
    );
    sizes.insert(
        "7AAA",
        Sizage {
            hs: 4,
            ss: 4,
            xs: 0,
            fs: None,
            ls: 0,
        },
    );
    sizes.insert(
        "8AAA",
        Sizage {
            hs: 4,
            ss: 4,
            xs: 0,
            fs: None,
            ls: 1,
        },
    );
    sizes.insert(
        "9AAA",
        Sizage {
            hs: 4,
            ss: 4,
            xs: 0,
            fs: None,
            ls: 2,
        },
    );

    sizes.insert(
        "4B",
        Sizage {
            hs: 2,
            ss: 2,
            xs: 0,
            fs: None,
            ls: 0,
        },
    );
    sizes.insert(
        "5B",
        Sizage {
            hs: 2,
            ss: 2,
            xs: 0,
            fs: None,
            ls: 1,
        },
    );
    sizes.insert(
        "6B",
        Sizage {
            hs: 2,
            ss: 2,
            xs: 0,
            fs: None,
            ls: 2,
        },
    );
    sizes.insert(
        "7AAB",
        Sizage {
            hs: 4,
            ss: 4,
            xs: 0,
            fs: None,
            ls: 0,
        },
    );
    sizes.insert(
        "8AAB",
        Sizage {
            hs: 4,
            ss: 4,
            xs: 0,
            fs: None,
            ls: 1,
        },
    );
    sizes.insert(
        "9AAB",
        Sizage {
            hs: 4,
            ss: 4,
            xs: 0,
            fs: None,
            ls: 2,
        },
    );

    sizes.insert(
        "4C",
        Sizage {
            hs: 2,
            ss: 2,
            xs: 0,
            fs: None,
            ls: 0,
        },
    );
    sizes.insert(
        "5C",
        Sizage {
            hs: 2,
            ss: 2,
            xs: 0,
            fs: None,
            ls: 1,
        },
    );
    sizes.insert(
        "6C",
        Sizage {
            hs: 2,
            ss: 2,
            xs: 0,
            fs: None,
            ls: 2,
        },
    );
    sizes.insert(
        "7AAC",
        Sizage {
            hs: 4,
            ss: 4,
            xs: 0,
            fs: None,
            ls: 0,
        },
    );
    sizes.insert(
        "8AAC",
        Sizage {
            hs: 4,
            ss: 4,
            xs: 0,
            fs: None,
            ls: 1,
        },
    );
    sizes.insert(
        "9AAC",
        Sizage {
            hs: 4,
            ss: 4,
            xs: 0,
            fs: None,
            ls: 2,
        },
    );

    sizes.insert(
        "4D",
        Sizage {
            hs: 2,
            ss: 2,
            xs: 0,
            fs: None,
            ls: 0,
        },
    );
    sizes.insert(
        "5D",
        Sizage {
            hs: 2,
            ss: 2,
            xs: 0,
            fs: None,
            ls: 1,
        },
    );
    sizes.insert(
        "6D",
        Sizage {
            hs: 2,
            ss: 2,
            xs: 0,
            fs: None,
            ls: 2,
        },
    );
    sizes.insert(
        "7AAD",
        Sizage {
            hs: 4,
            ss: 4,
            xs: 0,
            fs: None,
            ls: 0,
        },
    );
    sizes.insert(
        "8AAD",
        Sizage {
            hs: 4,
            ss: 4,
            xs: 0,
            fs: None,
            ls: 1,
        },
    );
    sizes.insert(
        "9AAD",
        Sizage {
            hs: 4,
            ss: 4,
            xs: 0,
            fs: None,
            ls: 2,
        },
    );

    sizes.insert(
        "4E",
        Sizage {
            hs: 2,
            ss: 2,
            xs: 0,
            fs: None,
            ls: 0,
        },
    );
    sizes.insert(
        "5E",
        Sizage {
            hs: 2,
            ss: 2,
            xs: 0,
            fs: None,
            ls: 1,
        },
    );
    sizes.insert(
        "6E",
        Sizage {
            hs: 2,
            ss: 2,
            xs: 0,
            fs: None,
            ls: 2,
        },
    );
    sizes.insert(
        "7AAE",
        Sizage {
            hs: 4,
            ss: 4,
            xs: 0,
            fs: None,
            ls: 0,
        },
    );
    sizes.insert(
        "8AAE",
        Sizage {
            hs: 4,
            ss: 4,
            xs: 0,
            fs: None,
            ls: 1,
        },
    );
    sizes.insert(
        "9AAE",
        Sizage {
            hs: 4,
            ss: 4,
            xs: 0,
            fs: None,
            ls: 2,
        },
    );

    sizes
}

/// Map of hard characters to their respective values
///
/// Includes:
/// - Uppercase letters (A-Z): value 1
/// - Lowercase letters (a-z): value 1
/// - Digits with varying values:
///   - '0','4','5','6': value 2
///   - '1','2','3','7','8','9': value 4
pub fn hards() -> HashMap<u8, i32> {
    let mut map: HashMap<u8, i32> = (b'A'..=b'Z').map(|c| (c, 1)).collect();

    // Add lowercase letters with value 1
    map.extend((b'a'..=b'z').map(|c| (c, 1)));

    // Add digits with specific values
    map.extend([
        (b'0', 2),
        (b'1', 4),
        (b'2', 4),
        (b'3', 4),
        (b'4', 2),
        (b'5', 2),
        (b'6', 2),
        (b'7', 4),
        (b'8', 4),
        (b'9', 4),
    ]);

    map
}

/// Converts a base64 character to its binary quadlet (2-bit) representation
fn code_b64_to_b2(c: u8) -> u8 {
    match c {
        b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'+' | b'/' => {
            let val = match c {
                b'A'..=b'Z' => c - b'A',
                b'a'..=b'z' => c - b'a' + 26,
                b'0'..=b'9' => c - b'0' + 52,
                b'+' => 62,
                b'/' => 63,
                _ => unreachable!(),
            };
            val
        }
        _ => b'0',
    }
}

/// Map of binary quadlet characters to their hardness values
/// This converts the base64 characters in the Hards map to their binary
/// representation and maps them to the same hardness values
pub fn get_bards() -> HashMap<u8, i32> {
    let hards = hards();
    hards
        .iter()
        .map(|(&c, &hs)| (code_b64_to_b2(c), hs))
        .collect()
}

/// Matter is a trait for fully qualified cryptographic material.
/// Implementations provide various specialized crypto material types.
pub trait Matter: Any {
    /// Returns the hard part of the derivation code
    fn code(&self) -> &str;

    /// Returns raw crypto material (without derivation code)
    fn raw(&self) -> &[u8];

    /// Returns base64 fully qualified representation
    fn qb64(&self) -> String;

    /// Returns base64 fully qualified representation
    fn qb64b(&self) -> Vec<u8>;

    /// Returns binary fully qualified representation
    fn qb2(&self) -> Vec<u8>;

    /// Soft portion of qb64 value
    fn soft(&self) -> &str;

    /// Return the full size of this Matter instance
    fn full_size(&self) -> usize;

    /// Calculate the populated size
    fn size(&self) -> usize;

    /// Returns whether the derivation code is transferable
    fn is_transferable(&self) -> bool;

    /// Returns whether the code represents a digest
    fn is_digestive(&self) -> bool;

    /// Returns whether the code represents a prefix
    fn is_prefixive(&self) -> bool;

    /// Returns whether the code represents a prefix
    fn is_special(&self) -> bool;

    fn as_any(&self) -> &dyn Any;
}

/// Trait that must be implemented by types that can be parsed
pub trait Parsable: Sized {
    fn from_qb64b(data: &mut Vec<u8>, strip: Option<bool>) -> Result<Self, MatterError>;
    fn from_qb2(data: &mut Vec<u8>, strip: Option<bool>) -> Result<Self, MatterError>;
}

/// Common implementation for all Matter types.
#[derive(Debug, Clone)]
pub struct BaseMatter {
    code: String,
    soft: String,
    raw: Vec<u8>,
}

impl BaseMatter {
    /// Creates a new BaseMatter from raw bytes and a code
    pub fn new(
        raw: Option<&[u8]>,
        code: Option<&str>,
        soft: Option<&str>,
        rize: Option<usize>,
    ) -> Result<Self, MatterError> {
        let code = code.ok_or_else(|| {
            MatterError::EmptyMaterial(
                "Improper initialization need either (raw not None and code) or \
             (code and soft) or qb64b or qb64 or qb2."
                    .to_string(),
            )
        })?;

        let raw =
            raw.ok_or_else(|| MatterError::TypeError(String::from("Raw data must be provided")))?;

        let sizes = get_sizes();
        // Check if code is supported
        if !sizes.contains_key(code) {
            return Err(MatterError::InvalidCode(format!(
                "Unsupported code={}",
                code
            )));
        }

        // Get sizes for this code
        let size = sizes[code].clone(); // Assumes valid sizes from unit tests
        let (_, ss, xs, fs, _) = (size.hs, size.ss, size.xs, size.fs, size.ls);
        let hs;
        let rize_val;
        let mut soft_val = String::new();
        let mut code_val = code.to_string();

        if fs.is_none() {
            // Variable sized - code[0] should be in SmallVrzDex or LargeVrzDex
            // Determine the size of raw data to use
            rize_val = match rize {
                Some(r) => r,
                None => raw.len(),
            };

            // Calculate actual lead (pad) size
            let ls = ((3 - (rize_val % 3)) % 3) as u32;
            // Calculate size in triplets
            let size = (rize_val + ls as usize) / 3;

            // Handle small vs large variable size codes
            if small_vrz_dex::TUPLE.contains(&&code[0..1]) {
                if size <= (64_usize.pow(2) - 1) {
                    // ss = 2
                    hs = 2;
                    let s = small_vrz_dex::TUPLE[ls as usize];
                    code_val = format!("{}{}", s, &code[1..hs as usize]);
                    soft_val = int_to_b64(size as u32, 2);
                } else if size <= (64_usize.pow(4) - 1) {
                    // ss = 4 make big version
                    hs = 4;
                    let s = large_vrz_dex::TUPLE[ls as usize];
                    code_val = format!("{}{}{}", s, "A".repeat(hs as usize - 2), &code[1..2]);
                    soft_val = int_to_b64(size as u32, 4);
                } else {
                    return Err(MatterError::InvalidVarRawSize(format!(
                        "Unsupported raw size for code={}",
                        code
                    )));
                }
            } else if large_vrz_dex::TUPLE.contains(&&code[0..1]) {
                if size <= (64_usize.pow(4) - 1) {
                    // ss = 4
                    hs = 4;
                    let s = large_vrz_dex::TUPLE[ls as usize];
                    code_val = format!("{}{}", s, &code[1..hs as usize]);
                    soft_val = int_to_b64(size as u32, 4);
                } else {
                    return Err(MatterError::InvalidVarRawSize(format!(
                        "Unsupported raw size for large code={}. {} <= {}",
                        code,
                        size,
                        64_usize.pow(4) - 1
                    )));
                }
            } else {
                return Err(MatterError::InvalidVarRawSize(format!(
                    "Unsupported variable raw size code={}",
                    code
                )));
            }
        } else {
            // Fixed size
            rize_val = raw_size(&code_val)?;

            if ss > 0 {
                // Special soft size, so soft must be provided
                let soft_str = soft.unwrap_or("");
                let trimmed_soft =
                    &soft_str[..std::cmp::min(soft_str.len(), ss as usize - xs as usize)];

                if trimmed_soft.len() != ss as usize - xs as usize {
                    return Err(MatterError::SoftMaterial(format!(
                        "Not enough chars in soft={} with ss={} xs={} for code={}",
                        soft_str, ss, xs, code
                    )));
                }

                // Check if all characters are Base64
                if !trimmed_soft
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
                {
                    return Err(MatterError::InvalidSoft(format!(
                        "Non Base64 chars in soft={}",
                        trimmed_soft
                    )));
                }

                soft_val = trimmed_soft.to_string();
            }
        }

        // Ensure raw has exactly the right size
        if raw.len() < rize_val {
            return Err(MatterError::RawMaterial(format!(
                "Not enough raw bytes for code={} expected rize={} got {}",
                code,
                rize_val,
                raw.len()
            )));
        }

        // Clone only the exact size needed from raw
        let raw_val = Vec::from(&raw[..rize_val]);

        Ok(BaseMatter {
            code: code_val,
            soft: soft_val,
            raw: raw_val,
            // Add other fields as needed
        })
    }

    pub fn from_raw(raw: Option<&[u8]>) -> Result<Self, MatterError> {
        BaseMatter::new(raw, Some(mtr_dex::ED25519N), None, None)
    }

    /// Creates a new BaseMatter from a qb64 string
    pub fn from_qb64(qb64: &str) -> Result<Self, MatterError> {
        if qb64.is_empty() {
            return Err(MatterError::ShortageError(
                "Empty qb64, invalid".to_string(),
            ));
        }

        let first = &qb64[0..1];

        let hards = hards();
        let sizes = get_sizes();
        // Check if first character is in Hards
        if !hards.contains_key(&first.bytes().next().unwrap_or(b'A')) {
            return if first == "-" {
                Err(MatterError::UnexpectedCountCodeError(
                    "Unexpected count code start while extracting Matter.".to_string(),
                ))
            } else if first == "_" {
                Err(MatterError::UnexpectedOpCodeError(
                    "Unexpected op code start while extracting Matter.".to_string(),
                ))
            } else {
                Err(MatterError::UnexpectedCodeError(format!(
                    "Unsupported code start char={}",
                    first
                )))
            };
        }

        let hs = *hards.get(&first.bytes().next().unwrap_or(b'A')).unwrap(); // get hard code size

        if qb64.len() < hs as usize {
            return Err(MatterError::ShortageError(format!(
                "Need {} more characters.",
                hs - qb64.len() as i32
            )));
        }

        let hard = &qb64[0..hs as usize];

        if !sizes.contains_key(hard) {
            return Err(MatterError::UnexpectedCodeError(format!(
                "Unsupported code ={}",
                hard
            )));
        }

        let size = *sizes.get(hard).unwrap();
        let cs = hs as u32 + size.ss; // both hs and ss

        // Extract soft chars including xtra, empty when ss==0 and xs == 0
        let soft = if size.ss > 0 {
            &qb64[hs as usize..(hs as u32 + size.ss) as usize]
        } else {
            ""
        };
        let xtra = if size.xs > 0 {
            &soft[0..size.xs as usize]
        } else {
            ""
        };
        let soft_without_xtra = if size.xs > 0 {
            &soft[size.xs as usize..]
        } else {
            soft
        };

        if size.xs > 0 && xtra != &"A".repeat(size.xs as usize) {
            return Err(MatterError::UnexpectedCodeError(format!(
                "Invalid prepad xtra ={}",
                xtra
            )));
        }

        let fs = if size.fs.is_none() {
            // compute fs from soft from ss part which provides size B64
            (b64_to_int(soft_without_xtra) * 4) + cs
        } else {
            size.fs.unwrap()
        };

        if qb64.len() < fs as usize {
            return Err(MatterError::ShortageError(format!(
                "Need {} more chars.",
                fs - qb64.len() as u32
            )));
        }

        let qb64 = &qb64[0..fs as usize]; // fully qualified primitive code plus material

        // Check for non-zeroed pad bits and/or lead bytes
        let ps = cs % 4; // net prepad bytes to ensure 24 bit align when encodeB64
        let base = "A".repeat(ps as usize) + &qb64[cs as usize..]; // prepad ps 'A's to B64 of (lead + raw)
        let paw = decode_b64(&base)?;

        // Ensure midpad bytes are zero
        let midpad = &paw[0..(ps + size.ls) as usize];
        let pi = u32::from_be_bytes([
            if midpad.len() > 0 { midpad[0] } else { 0 },
            if midpad.len() > 1 { midpad[1] } else { 0 },
            if midpad.len() > 2 { midpad[2] } else { 0 },
            if midpad.len() > 3 { midpad[3] } else { 0 },
        ]);

        if pi != 0 {
            return Err(MatterError::ConversionError(format!(
                "Nonzero midpad bytes=0x{:0width$x}.",
                pi,
                width = (ps + size.ls) as usize * 2
            )));
        }

        // Remove prepad midpat bytes to invert back to raw
        let raw = paw[(ps + size.ls) as usize..].to_vec();

        let expected_len = ((qb64.len() - cs as usize) * 3 / 4) - size.ls as usize;
        if raw.len() != expected_len {
            return Err(MatterError::ConversionError(format!(
                "Improperly qualified material = {}",
                qb64
            )));
        }

        Ok(Self {
            code: hard.to_string(),
            soft: soft.to_string(),
            raw,
        })
    }

    pub fn bexfil(qb2: &[u8]) -> Result<Self, MatterError> {
        if qb2.is_empty() {
            return Err(MatterError::Shortage(
                "Empty material, Need more bytes.".into(),
            ));
        }

        // Extract first sextet as code selector
        let first = nab_sextets(qb2, 1)?;

        let bards = get_bards();
        let hs = match bards.get(&first[0]) {
            Some(hs) => *hs,
            None => {
                return if first[0] == 0xf8 {
                    // b64ToB2('-')
                    Err(MatterError::UnexpectedCountCode(
                        "Unexpected count code start while extracting Matter.".into(),
                    ))
                } else if first[0] == 0xfc {
                    // b64ToB2('_')
                    Err(MatterError::UnexpectedOpCode(
                        "Unexpected op code start while extracting Matter.".into(),
                    ))
                } else {
                    Err(MatterError::UnexpectedCode(format!(
                        "Unsupported code start sextet={:02x?}.",
                        first
                    )))
                };
            }
        };

        // bhs is min bytes to hold hs sextets
        let bhs = ((hs as f64) * 3.0 / 4.0).ceil() as usize;
        if qb2.len() < bhs {
            return Err(MatterError::Shortage(format!(
                "Need {} more bytes.",
                bhs - qb2.len()
            )));
        }

        // Extract and convert hard part of code
        let hard = code_b2_to_b64(qb2, hs as usize)?;

        let sizes = get_sizes();
        let size = sizes[hard.as_str()].clone();
        let (hs, ss, xs, fs, ls) = (size.hs, size.ss, size.xs, size.fs, size.ls);
        let cs = hs + ss; // both hs and ss

        // bcs is min bytes to hold cs sextets
        let bcs = ((cs as f64) * 3.0 / 4.0).ceil() as usize;
        if qb2.len() < bcs {
            return Err(MatterError::Shortage(format!(
                "Need {} more bytes.",
                bcs - qb2.len()
            )));
        }

        // Extract and convert both hard and soft part of code
        let both = code_b2_to_b64(qb2, cs as usize)?;

        // Extract soft chars including xtra, empty when ss==0 and xs == 0
        // Assumes that when ss == 0 then xs must be 0
        let mut soft = both[hs as usize..].to_string();
        let xtra = if xs > 0 {
            soft[..xs as usize].to_string()
        } else {
            String::new()
        };

        if xs > 0 {
            soft = soft[xs as usize..].to_string();
        }

        // Check for valid padding in xtra
        if xs > 0 && xtra != PAD.to_string().repeat(xs as usize) {
            return Err(MatterError::UnexpectedCode(format!(
                "Invalid prepad xtra ={}",
                xtra
            )));
        }

        // Calculate the full size (fs)
        let calculated_fs = if fs.unwrap_or(0) == 0 {
            // Compute fs from size chars in ss part of code
            if qb2.len() < bcs {
                return Err(MatterError::Shortage(format!(
                    "Need {} more bytes.",
                    bcs - qb2.len()
                )));
            }

            // Compute size as int from soft part given by ss B64 chars
            let soft_int = b64_to_int(&soft);
            (soft_int * 4) + cs
        } else {
            fs.unwrap_or(0)
        };

        // bfs is min bytes to hold fs sextets
        let bfs = ((calculated_fs as f64) * 3.0 / 4.0).ceil() as usize;
        if qb2.len() < bfs {
            return Err(MatterError::Shortage(format!(
                "Need {} more bytes.",
                bfs - qb2.len()
            )));
        }

        let qb2 = &qb2[..bfs]; // Extract qb2 fully qualified primitive code plus material

        // Check for nonzero trailing full code mid pad bits
        let ps = cs % 4; // Full code (both) net pad size for 24 bit alignment
        let pbs = 2 * ps; // Mid pad bits = 2 per net pad

        if pbs > 0 {
            // Get pad bits in last byte of full code
            let pi = qb2[bcs - 1];
            let mask = (1 << pbs) - 1; // Mask with 1's in pad bit locations
            if pi & mask != 0 {
                // Not zero so raise error
                return Err(MatterError::Conversion(format!(
                    "Nonzero code mid pad bits=0b{:0width$b}.",
                    pi & mask,
                    width = pbs as usize
                )));
            }
        }

        // Check nonzero leading mid pad lead bytes in lead + raw
        if ls > 0 {
            let mut lead_bytes = vec![0u8; ls as usize];
            lead_bytes.copy_from_slice(&qb2[bcs..bcs + ls as usize]);

            let mut is_zero = true;
            for byte in &lead_bytes {
                if *byte != 0 {
                    is_zero = false;
                    break;
                }
            }

            if !is_zero {
                return Err(MatterError::Conversion(format!(
                    "Nonzero lead midpad bytes={:0width$x?}.",
                    lead_bytes,
                    width = (ls * 2) as usize
                )));
            }
        }

        // Strip code and leader bytes from qb2 to get raw
        let raw = if (bcs + ls as usize) < qb2.len() {
            qb2[bcs + ls as usize..].to_vec()
        } else {
            Vec::new()
        };

        if raw.len() != (qb2.len() - bcs - ls as usize) {
            return Err(MatterError::Conversion(format!(
                "Improperly qualified material = {:?}",
                qb2
            )));
        }

        // Update the struct fields
        Ok(Self {
            code: hard.to_string(),
            soft,
            raw,
        })
    }

    /// Creates a new BaseMatter instance from soft and code components
    ///
    /// # Arguments
    /// * `soft` - The soft part of the code as a string slice
    /// * `code` - The hard part of the code as a string slice
    ///
    /// # Returns
    /// * `Result<Self, MatterError>` - A BaseMatter instance or an error
    fn from_soft_and_code(soft: &str, code: &str) -> Result<Self, MatterError> {
        // Get the sizes associated with the given code
        let sizes = get_sizes();
        let size = sizes[code].clone();
        let (hs, ss, xs, fs, ls) = (size.hs, size.ss, size.xs, size.fs.unwrap_or(0), size.ls);

        // Check if code is a variable sized code
        if fs == 0 {
            return Err(MatterError::InvalidSoftError(format!(
                "Unsupported variable sized code={} with fs={} for special soft={}.",
                code, fs, soft
            )));
        }

        // Check if it's not a special soft - validate ss, fs, hs, and ls
        if !(ss > 0) || (fs == hs + ss && ls != 0) {
            return Err(MatterError::InvalidSoftError(format!(
                "Invalid soft size={} or lead={} or code={} fs={} when special soft.",
                ss, ls, code, fs
            )));
        }

        // Trim soft to correct length
        let trimmed_soft = if soft.len() >= (ss - xs) as usize {
            &soft[0..(ss - xs) as usize]
        } else {
            return Err(MatterError::SoftMaterialError(format!(
                "Not enough chars in soft={} with ss={} xs={} for code={}.",
                soft, ss, xs, code
            )));
        };

        // Validate that soft contains only Base64 characters
        if !is_base64(trimmed_soft) {
            return Err(MatterError::InvalidSoftError(format!(
                "Non Base64 chars in soft={}.",
                trimmed_soft
            )));
        }

        // Return populated BaseMatter struct
        Ok(BaseMatter {
            code: code.to_string(),
            soft: trimmed_soft.to_string(),
            raw: Vec::new(), // Empty raw bytes as in Python: self._raw = b''
        })
    }

    fn infil(&self) -> Result<String, MatterError> {
        let code = &self.code; // hard part of full code == codex value
        let both = format!("{}{}", self.code, self.soft); // code + soft, soft may be empty
        let raw = &self.raw; // bytes, raw may be empty
        let rs = raw.len(); // raw size

        // Get sizes from the Sizes table based on the code
        let sizes = get_sizes();
        let size = sizes[code.as_str()];
        let (hs, ss, xs, fs, ls) = (size.hs, size.ss, size.xs, size.fs, size.ls);
        let cs = hs + ss;

        // Verify the code size is valid
        if cs != both.len() as u32 {
            return Err(MatterError::InvalidCodeSize(format!(
                "Invalid full code={} for sizes hs={} and ss={}.",
                both, hs, ss
            )));
        }

        let full = if fs.unwrap_or(0) == 0 {
            // Variable sized
            // Ensure that (ls + rs) % 3 == 0 and cs % 4 == 0
            if (ls + rs as u32) % 3 != 0 || cs % 4 != 0 {
                return Err(MatterError::InvalidCodeSize(format!(
                    "Invalid full code both={} with variable raw size={} given cs={}, hs={}, ss={}, fs={}, and ls={}.",
                    both, rs, cs, hs, ss, fs.unwrap_or(0), ls
                )));
            }

            // Prepad raw with ls zero bytes and convert
            let mut padded_raw = vec![0; ls as usize];
            padded_raw.extend_from_slice(raw);
            let encoded = encode_b64(&padded_raw);

            format!("{}{}", both, encoded)
        } else {
            // Fixed size
            let ps = (3 - ((rs + ls as usize) % 3)) % 3; // net pad size given raw with lead

            // Check if pad size matches code size remainder
            if ps != (cs % 4) as usize {
                return Err(MatterError::InvalidCodeSize(format!(
                    "Invalid full code both={} with fixed raw size={} given cs={}, hs={}, ss={}, fs={}, and ls={}.",
                    both, rs, cs, hs, ss, fs.unwrap_or(0), ls
                )));
            }

            // Prepad raw with ps+ls zero bytes
            let mut padded_raw = vec![0; ps + ls as usize];
            padded_raw.extend_from_slice(raw);
            let encoded = encode_b64(&padded_raw);

            // Skip first ps == cs % 4 of the converted characters
            format!("{}{}", both, &encoded[ps..])
        };

        // Final validation
        if (full.len() % 4 != 0) || (fs.unwrap_or(0) > 0 && full.len() != fs.unwrap_or(0) as usize)
        {
            return Err(MatterError::InvalidCodeSize(format!(
                "Invalid full size given code both={} with raw size={}, cs={}, hs={}, ss={}, xs={}, fs={}, and ls={}.",
                both, rs, cs, hs, ss, xs, fs.unwrap_or(0), ls
            )));
        }

        Ok(full)
    }

    /// Create binary domain representation
    ///
    /// Returns bytes of fully qualified base2 bytes, that is .qb2
    /// self.code converted to Base2 + self.raw left shifted with pad bits
    /// equivalent of Base64 decode of .qb64 into .qb2
    pub fn binfil(&self) -> Result<Vec<u8>, MatterError> {
        let code = &self.code; // hard part of full code == codex value
        let both = format!("{}{}", &self.code, &self.soft); // code + soft, soft may be empty
        let raw = &self.raw; // bytes may be empty

        // Get sizes from the Sizes table based on the code
        let sizes = get_sizes();
        let size = sizes[code.as_str()];
        let (hs, ss, fs, ls) = (size.hs, size.ss, size.fs, size.ls);
        let cs = hs + ss;
        // assumes unit tests on BaseMatter.get_sizes ensure valid size entries

        // Number of b2 bytes to hold b64 code
        let n = ((cs * 3) as f64 / 4.0).ceil() as usize; // sceil equivalent

        // Convert code both to right align b2 int then left shift in pad bits
        // then convert to bytes
        let b64_int = b64_to_int(&both);
        let shift = 2 * (cs % 4);
        let b64_shifted = b64_int << shift;

        // Create bytes from the shifted integer
        let bcode = b64_shifted.to_be_bytes()[b64_shifted.to_be_bytes().len() - n..].to_vec();

        // Combine bcode with lead bytes and raw data
        let mut full = Vec::new();
        full.extend_from_slice(&bcode);
        full.extend_from_slice(&vec![0; ls as usize]);
        full.extend_from_slice(raw);

        let bfs = full.len();

        // Compute fs if not provided (variable size)
        let calculated_fs = if fs.unwrap_or(0) == 0 {
            hs + ss + ((raw.len() as u32 + ls) * 4) / 3
        } else {
            fs.unwrap()
        };

        // Validate size
        if bfs % 3 != 0 || ((bfs * 4) / 3) != calculated_fs as usize {
            return Err(MatterError::InvalidCodeSize(format!(
                "Invalid full code={} for raw size={}.",
                both,
                raw.len()
            )));
        }

        Ok(full)
    }
}

impl Parsable for BaseMatter {
    fn from_qb64b(data: &mut Vec<u8>, strip: Option<bool>) -> Result<Self, MatterError> {
        let qb64b = data.as_slice();
        let qb64 = str::from_utf8(qb64b).ok();
        let mtr = BaseMatter::from_qb64(qb64.unwrap_or(""))?;
        if strip.unwrap_or(false) {
            let fs = mtr.full_size();
            data.drain(..fs);
        }
        Ok(mtr)
    }

    /// Creates a new BaseMatter from qb2 bytes
    fn from_qb2(data: &mut Vec<u8>, strip: Option<bool>) -> Result<Self, MatterError> {
        let qb2 = data.as_slice();
        let mtr = BaseMatter::bexfil(qb2)?;
        if strip.unwrap_or(false) {
            let fs = mtr.full_size();
            data.drain(..fs);
        }
        Ok(mtr)
    }
}

// Helper function to decode base64 string to bytes
fn decode_b64(data: &str) -> Result<Vec<u8>, MatterError> {
    general_purpose::URL_SAFE_NO_PAD
        .decode(data)
        .map_err(|_| MatterError::InvalidBase64)
}

fn encode_b64(data: &[u8]) -> String {
    general_purpose::URL_SAFE_NO_PAD.encode(data)
}

// Helper function to convert base64 string to integer
pub fn b64_to_int(b64_str: &str) -> u32 {
    let mut result = 0u32;
    for c in b64_str.chars() {
        result = result * 64
            + match c {
                'A'..='Z' => c as u32 - 'A' as u32,
                'a'..='z' => c as u32 - 'a' as u32 + 26,
                '0'..='9' => c as u32 - '0' as u32 + 52,
                '+' | '-' => 62,
                '/' | '_' => 63,
                _ => 0,
            };
    }
    result
}

// Helper function to convert integer to base64 string
pub fn int_to_b64(num: u32, length: usize) -> String {
    const B64_CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    let mut result = String::with_capacity(length);
    let mut n = num;

    for _ in 0..length {
        let idx = (n % 64) as usize;
        result.insert(0, B64_CHARS[idx] as char);
        n /= 64;
    }

    result
}

pub fn raw_size(code: &str) -> Result<usize, MatterError> {
    // Implementation would access self.sizes to get the raw size for this code
    // For this example, we'll return a placeholder
    // In the actual implementation, this would look up the size from the Sizes map
    let sizes = get_sizes();
    let size = sizes[code].clone();
    let cs = size.hs + size.ss;
    let fs = size
        .fs
        .ok_or_else(|| MatterError::InvalidCode(code.to_string()))?;

    Ok((((fs - cs) * 3 / 4) - size.ls) as usize)
}

/// Nab l sextets from front of b
///
/// # Returns
/// Bytes containing first l sextets from front (left) of b as a Vec<u8>.
/// Length of bytes returned is minimum sufficient to hold all l sextets.
/// Last byte returned is right bit padded with zeros which is compatible
/// with mid padded codes on front of primitives.
///
/// # Parameters
/// * `b`: target from which to nab sextets
/// * `l`: number of sextets to nab from front of b
///
/// # Errors
/// Returns an error message if there aren't enough bytes in b to nab l sextets.
pub fn nab_sextets(b: &[u8], l: usize) -> Result<Vec<u8>, MatterError> {
    // Calculate number of bytes needed for l sextets (ceiling of l*3/4)
    let n = (l * 3 + 3) / 4; // Equivalent to ceiling of l*3/4

    if n > b.len() {
        return Err(MatterError::ShortageError(format!(
            "Not enough bytes in {:?} to nab {} sextets.",
            b, l
        )));
    }

    // Extract the first n bytes and convert to a BigUint
    let bytes = &b[..n];
    let mut i = BigUint::from_bytes_be(bytes);

    // Calculate padding bits based on l % 4
    let p = 2 * (l % 4);

    if p > 0 {
        // Apply bit shifting operations
        // i >>= p  (strip off last bits)
        i >>= p;

        // i <<= p  (pad with empty bits)
        i <<= p;
    }

    // Convert back to bytes
    let mut result = i.to_bytes_be();

    // Ensure the result is exactly n bytes by padding with zeros if needed
    if result.len() < n {
        let padding = vec![0; n - result.len()];
        let mut padded_result = padding;
        padded_result.extend(result);
        result = padded_result;
    }

    Ok(result)
}

/// Convert l sextets from base2 b to base64
///
/// # Returns
/// A String containing the conversion (encode) of l Base2 sextets from front of b
/// to Base64 chars. One char for each of l sextets from front (left) of b.
///
/// This is useful for encoding as code characters, sextets from the front of
/// a Base2 bytes. Must provide l because of ambiguity between l=3
/// and l=4. Both require 3 bytes in b. Trailing pad bits are removed so
/// returned sextets as characters are right aligned.
///
/// # Parameters
/// * `b`: target from which to nab sextets
/// * `l`: number of sextets to convert from front of b
///
/// # Errors
/// Returns an error message if there aren't enough bytes in b to nab l sextets.
pub fn code_b2_to_b64(b: &[u8], l: usize) -> Result<String, MatterError> {
    // Calculate number of bytes needed for l sextets (ceiling of l*3/4)
    let n = (l * 3 + 3) / 4; // Equivalent to ceiling of l*3/4

    if n > b.len() {
        return Err(MatterError::ShortageError(format!(
            "Not enough bytes in {:?} to nab {} sextets.",
            b, l
        )));
    }

    // Extract the first n bytes and convert to a BigUint
    let bytes = &b[..n];
    let i = BigUint::from_bytes_be(bytes);

    // Calculate trailing bit size in bits
    let tbs = 2 * (l % 4);

    // Right shift out trailing bits to make right aligned
    let adjusted_i = if tbs > 0 { i >> tbs } else { i };

    let result = adjusted_i.to_u64().unwrap_or_else(|| 0);
    // Return as Base64
    Ok(int_to_b64(result as u32, l))
}

// Helper function to check if a string contains only Base64 characters
fn is_base64(s: &str) -> bool {
    s.chars().all(|c| {
        (c >= 'A' && c <= 'Z')
            || (c >= 'a' && c <= 'z')
            || (c >= '0' && c <= '9')
            || c == '+'
            || c == '/'
            || c == '-'
            || c == '_'
    })
}

impl Matter for BaseMatter {
    fn code(&self) -> &str {
        &self.code
    }

    fn raw(&self) -> &[u8] {
        &self.raw
    }

    fn qb64(&self) -> String {
        let result = self.infil();
        result.unwrap()
    }

    fn qb64b(&self) -> Vec<u8> {
        let result = self.infil();
        result.unwrap().into_bytes()
    }

    fn qb2(&self) -> Vec<u8> {
        let result = self.binfil();
        result.unwrap()
    }

    fn soft(&self) -> &str {
        &self.soft
    }

    /// Returns full size of matter in bytes
    ///
    /// Fixed size codes returns fs from .Sizes
    /// Variable size codes where fs==None computes fs from .size and sizes
    ///
    /// # Returns
    /// * `usize` - Full size in bytes
    fn full_size(&self) -> usize {
        // Extract sizes from the Sizes map using the code
        let sizes = get_sizes();
        let size = sizes[self.code.as_str()];
        let (hs, ss, fs) = (size.hs, size.ss, size.fs);

        // If fs is None, compute the full size
        match fs {
            Some(fixed_size) => fixed_size as usize,
            None => {
                // Compute fs from ss characters in code and self.size
                (hs + ss) as usize + (self.size() * 4)
            }
        }
    }

    fn size(&self) -> usize {
        let soft = self.soft();
        if soft.len() == 0 {
            0
        } else {
            b64_to_int(self.soft()) as usize
        }
    }

    fn is_transferable(&self) -> bool {
        !non_trans_dex::TUPLE.contains(&(self.code.as_str()))
    }

    fn is_digestive(&self) -> bool {
        dig_dex::TUPLE.contains(&(self.code.as_str()))
    }

    fn is_prefixive(&self) -> bool {
        pre_dex::TUPLE.contains(&(self.code.as_str()))
    }

    fn is_special(&self) -> bool {
        let sizes = get_sizes();
        let size = sizes[self.code.as_str()];

        match size.fs {
            Some(_) => size.ss > 0,
            None => false,
        }
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base_matter_from_qb64() {
        // Given input qb64 string
        let qb64 = "BGlOiUdp5sMmfotHfCWQKEzWR91C72AH0lT84c0um-Qj";

        // Expected raw value (in Rust byte string)
        let expected_raw =
            b"iN\x89Gi\xe6\xc3&~\x8bG|%\x90(L\xd6G\xddB\xef`\x07\xd2T\xfc\xe1\xcd.\x9b\xe4#";

        let prebin: [u8; 33] = [
            0x04, 0x69, 0x4E, 0x89, 0x47, 0x69, 0xE6, 0xC3, 0x26, 0x7E, 0x8B, 0x47, 0x7C, 0x25,
            0x90, 0x28, 0x4C, 0xD6, 0x47, 0xDD, 0x42, 0xEF, 0x60, 0x07, 0xD2, 0x54, 0xFC, 0xE1,
            0xCD, 0x2E, 0x9B, 0xE4, 0x23,
        ];

        // When converting from qb64
        let matter = BaseMatter::from_qb64(qb64).expect("Failed to create BaseMatter from qb64");

        assert_eq!(matter.raw(), expected_raw);
        assert_eq!(matter.code(), "B");
        assert_eq!(matter.qb64(), qb64);
        assert_eq!(matter.qb2(), prebin.to_vec());
    }

    #[test]
    fn test_base_matter_from_raw() {
        let raw = b"iN\x89Gi\xe6\xc3&~\x8bG|%\x90(L\xd6G\xddB\xef`\x07\xd2T\xfc\xe1\xcd.\x9b\xe4#";
        let prebin: [u8; 33] = [
            0x04, 0x69, 0x4E, 0x89, 0x47, 0x69, 0xE6, 0xC3, 0x26, 0x7E, 0x8B, 0x47, 0x7C, 0x25,
            0x90, 0x28, 0x4C, 0xD6, 0x47, 0xDD, 0x42, 0xEF, 0x60, 0x07, 0xD2, 0x54, 0xFC, 0xE1,
            0xCD, 0x2E, 0x9B, 0xE4, 0x23,
        ];

        let matter = BaseMatter::new(Some(raw), Some("B"), None, None).unwrap();
        assert_eq!(matter.raw(), raw);
        assert_eq!(matter.code(), "B");
        assert_eq!(
            matter.qb64(),
            "BGlOiUdp5sMmfotHfCWQKEzWR91C72AH0lT84c0um-Qj"
        );
        assert_eq!(matter.qb2(), prebin.to_vec());

        let matter1 = BaseMatter::from_raw(Some(raw)).unwrap();
        assert_eq!(matter1.raw(), raw);
        assert_eq!(matter1.code(), "B");
        assert_eq!(
            matter1.qb64(),
            "BGlOiUdp5sMmfotHfCWQKEzWR91C72AH0lT84c0um-Qj"
        );
        assert_eq!(matter1.qb2(), prebin.to_vec());

        let matter2 = BaseMatter::from_qb2(&mut prebin.to_vec(), None).unwrap();
        assert_eq!(matter2.raw(), raw);
        assert_eq!(matter2.code(), "B");
        assert_eq!(
            matter2.qb64(),
            "BGlOiUdp5sMmfotHfCWQKEzWR91C72AH0lT84c0um-Qj"
        );
    }

    #[test]
    fn test_matter_codex() {
        let sizes = get_sizes();
        // Test that MtrDex constants are defined correctly
        assert_eq!(mtr_dex::ED25519_SEED, "A");
        assert_eq!(mtr_dex::ED25519N, "B");
        assert_eq!(mtr_dex::X25519, "C");
        assert_eq!(mtr_dex::ED25519, "D");
        assert_eq!(mtr_dex::BLAKE3_256, "E");
        assert_eq!(mtr_dex::BLAKE2B_256, "F");
        assert_eq!(mtr_dex::BLAKE2S_256, "G");
        assert_eq!(mtr_dex::SHA3_256, "H");
        assert_eq!(mtr_dex::SHA2_256, "I");

        // Test that Sizage values are correct for some codes
        let size = sizes[mtr_dex::ED25519_SEED];
        assert_eq!(size.hs, 1);
        assert_eq!(size.ss, 0);
        assert_eq!(size.xs, 0);
        assert_eq!(size.fs, Some(44));
        assert_eq!(size.ls, 0);

        let size = sizes[mtr_dex::ED25519N];
        assert_eq!(size.hs, 1);
        assert_eq!(size.ss, 0);
        assert_eq!(size.xs, 0);
        assert_eq!(size.fs, Some(44));
        assert_eq!(size.ls, 0);

        let size = sizes[mtr_dex::BLAKE3_256];
        assert_eq!(size.hs, 1);
        assert_eq!(size.ss, 0);
        assert_eq!(size.xs, 0);
        assert_eq!(size.fs, Some(44));
        assert_eq!(size.ls, 0);

        // Test raw_size function
        assert_eq!(raw_size(mtr_dex::ED25519).unwrap(), 32);
        assert_eq!(raw_size(mtr_dex::ED25519N).unwrap(), 32);
        assert_eq!(raw_size(mtr_dex::BLAKE3_256).unwrap(), 32);
    }

    #[test]
    fn test_matter_basic() {
        // Test with empty material
        let result = BaseMatter::new(None, None, None, None);
        assert!(result.is_err());

        // Test with raw bytes but no code
        let verkey =
            b"iN\x89Gi\xe6\xc3&~\x8bG|%\x90(L\xd6G\xddB\xef`\x07\xd2T\xfc\xe1\xcd.\x9b\xe4#";
        let result = BaseMatter::new(Some(verkey), None, None, None);
        assert!(result.is_err());

        // Test with valid raw and code
        let result = BaseMatter::new(Some(verkey), Some(mtr_dex::ED25519N), None, None);
        assert!(result.is_ok());
        let matter = result.unwrap();
        assert_eq!(matter.code(), mtr_dex::ED25519N);
        assert_eq!(matter.raw(), verkey);

        // Test qb64 generation
        let qb64 = matter.qb64();
        assert_eq!(qb64, "BGlOiUdp5sMmfotHfCWQKEzWR91C72AH0lT84c0um-Qj");

        // Test from qb64
        let matter2 = BaseMatter::from_qb64(&qb64).unwrap();
        assert_eq!(matter2.code(), mtr_dex::ED25519N);
        assert_eq!(matter2.raw(), verkey);
        assert_eq!(matter2.qb64(), qb64);

        // Test qb2 generation and conversion
        let qb2 = matter.qb2();
        let matter3 = BaseMatter::from_qb2(&mut qb2.to_vec(), None).unwrap();
        assert_eq!(matter3.code(), mtr_dex::ED25519N);
        assert_eq!(matter3.raw(), verkey);
        assert_eq!(matter3.qb64(), qb64);

        // Test transferable property
        assert!(!matter.is_transferable());

        // Test with transferable code
        let result = BaseMatter::new(Some(verkey), Some(mtr_dex::ED25519), None, None);
        assert!(result.is_ok());
        let matter = result.unwrap();
        assert_eq!(matter.code(), mtr_dex::ED25519);
        assert!(matter.is_transferable());

        // Test digestive property
        assert!(!matter.is_digestive());

        // Test with digest code
        let digest = [0u8; 32];
        let result = BaseMatter::new(
            Some(digest.as_slice()),
            Some(mtr_dex::BLAKE3_256),
            None,
            None,
        );
        assert!(result.is_ok());
        let matter = result.unwrap();
        assert_eq!(matter.code(), mtr_dex::BLAKE3_256);
        assert!(matter.is_digestive());

        // Test prefixive property
        assert!(matter.is_prefixive());
    }

    #[test]
    fn test_matter_from_qb64() {
        let prefix = "BGlOiUdp5sMmfotHfCWQKEzWR91C72AH0lT84c0um-Qj";
        let matter = BaseMatter::from_qb64(prefix).unwrap();
        assert_eq!(matter.code(), mtr_dex::ED25519N);
        assert_eq!(matter.qb64(), prefix);

        // Test with full identifier
        let both = format!("{}:mystuff/mypath/toresource?query=what#fragment", prefix);
        let matter = BaseMatter::from_qb64(&both).unwrap();
        assert_eq!(matter.code(), mtr_dex::ED25519N);
        assert_eq!(matter.qb64(), prefix);
        assert!(!matter.is_transferable());
        assert!(!matter.is_digestive());
        assert!(matter.is_prefixive());
    }

    #[test]
    fn test_matter_from_qb64b() {
        let prefix = "BGlOiUdp5sMmfotHfCWQKEzWR91C72AH0lT84c0um-Qj";
        let mut prefixb = prefix.as_bytes().to_vec();
        let matter = BaseMatter::from_qb64b(&mut prefixb, None).unwrap();
        assert_eq!(matter.code(), mtr_dex::ED25519N);
        assert_eq!(matter.qb64(), prefix);

        // Test with full identifier
        let both = format!("{}:mystuff/mypath/toresource?query=what#fragment", prefix);
        let mut bothb = both.as_bytes().to_vec();
        let matter = BaseMatter::from_qb64b(&mut bothb, None).unwrap();
        assert_eq!(matter.code(), mtr_dex::ED25519N);
        assert_eq!(matter.qb64(), prefix);
        assert!(!matter.is_transferable());
        assert!(!matter.is_digestive());
        assert!(matter.is_prefixive());
    }

    #[test]
    fn test_matter_from_qb2() {
        let prefix = "BGlOiUdp5sMmfotHfCWQKEzWR91C72AH0lT84c0um-Qj";
        let matter = BaseMatter::from_qb64(prefix).unwrap();
        let mut qb2 = matter.qb2();

        let matter2 = BaseMatter::from_qb2(&mut qb2, None).unwrap();
        assert_eq!(matter2.code(), mtr_dex::ED25519N);
        assert_eq!(matter2.qb64(), prefix);
        assert!(!matter2.is_transferable());
        assert!(!matter2.is_digestive());
        assert!(matter2.is_prefixive());
    }

    #[test]
    fn test_matter_with_fixed_sizes() {
        // Test TBD0 code with fixed size and lead size 0
        let code = mtr_dex::TBD0;
        let raw = b"abc";
        let qb64 = "1___YWJj";

        let matter = BaseMatter::new(Some(raw), Some(code), None, None).unwrap();
        assert_eq!(matter.code(), code);
        assert_eq!(matter.raw(), raw);
        assert_eq!(matter.qb64(), qb64);
        assert!(matter.is_transferable());
        assert!(!matter.is_digestive());
        assert!(!matter.is_prefixive());

        let matter2 = BaseMatter::from_qb64(qb64).unwrap();
        assert_eq!(matter2.code(), code);
        assert_eq!(matter2.raw(), raw);

        // Test TBD1 code with fixed size and lead size 1
        let code = mtr_dex::TBD1;
        let raw = b"ab";
        let qb64 = "2___AGFi";

        let matter = BaseMatter::new(Some(raw), Some(code), None, None).unwrap();
        assert_eq!(matter.code(), code);
        assert_eq!(matter.raw(), raw);
        assert_eq!(matter.qb64(), qb64);
        assert!(matter.is_transferable());
        assert!(!matter.is_digestive());
        assert!(!matter.is_prefixive());

        let matter2 = BaseMatter::from_qb64(qb64).unwrap();
        assert_eq!(matter2.code(), code);
        assert_eq!(matter2.raw(), raw);

        // Test TBD2 code with fixed size and lead size 2
        let code = mtr_dex::TBD2;
        let raw = b"z";
        let qb64 = "3___AAB6";

        let matter = BaseMatter::new(Some(raw), Some(code), None, None).unwrap();
        assert_eq!(matter.code(), code);
        assert_eq!(matter.raw(), raw);
        assert_eq!(matter.qb64(), qb64);
        assert!(matter.is_transferable());
        assert!(!matter.is_digestive());
        assert!(!matter.is_prefixive());

        let matter2 = BaseMatter::from_qb64(qb64).unwrap();
        assert_eq!(matter2.code(), code);
        assert_eq!(matter2.raw(), raw);
    }

    #[test]
    fn test_matter_with_variable_sizes() {
        // Test Bytes_L0 code with variable size and lead size 0
        let code = mtr_dex::BYTES_L0;
        let raw = b"abcdef";
        let qb64 = "4BACYWJjZGVm";

        let matter = BaseMatter::new(Some(raw), Some(code), None, None).unwrap();
        assert_eq!(matter.code(), code);
        assert_eq!(matter.raw(), raw);
        assert_eq!(matter.qb64(), qb64);
        assert!(matter.is_transferable());
        assert!(!matter.is_digestive());
        assert!(!matter.is_prefixive());

        let matter2 = BaseMatter::from_qb64(qb64).unwrap();
        assert_eq!(matter2.code(), code);
        assert_eq!(matter2.raw(), raw);

        // Test Bytes_L1 code with variable size and lead size 1
        let code = mtr_dex::BYTES_L1;
        let raw = b"abcde";
        let qb64 = "5BACAGFiY2Rl";

        let matter = BaseMatter::new(Some(raw), Some(code), None, None).unwrap();
        assert_eq!(matter.code(), code);
        assert_eq!(matter.raw(), raw);
        assert_eq!(matter.qb64(), qb64);
        assert!(matter.is_transferable());
        assert!(!matter.is_digestive());
        assert!(!matter.is_prefixive());

        let matter2 = BaseMatter::from_qb64(qb64).unwrap();
        assert_eq!(matter2.code(), code);
        assert_eq!(matter2.raw(), raw);

        // Test Bytes_L2 code with variable size and lead size 2
        let code = mtr_dex::BYTES_L2;
        let raw = b"abcd";
        let qb64 = "6BACAABhYmNk";

        let matter = BaseMatter::new(Some(raw), Some(code), None, None).unwrap();
        assert_eq!(matter.code(), code);
        assert_eq!(matter.raw(), raw);
        assert_eq!(matter.qb64(), qb64);
        assert!(matter.is_transferable());
        assert!(!matter.is_digestive());
        assert!(!matter.is_prefixive());

        let matter2 = BaseMatter::from_qb64(qb64).unwrap();
        assert_eq!(matter2.code(), code);
        assert_eq!(matter2.raw(), raw);
    }

    #[test]
    fn test_matter_with_special_codes() {
        // Test Tag3 code with special soft value
        let code = mtr_dex::TAG3;
        let soft = "icp";
        let qb64 = "Xicp";
        let raw = b"";

        let matter = BaseMatter::from_soft_and_code(soft, code).unwrap();
        assert_eq!(matter.code(), code);
        assert_eq!(matter.soft.as_str(), soft);
        assert_eq!(matter.raw(), raw);
        assert_eq!(matter.qb64(), qb64);
        assert!(matter.is_special());

        let matter2 = BaseMatter::from_qb64(qb64).unwrap();
        assert_eq!(matter2.code(), code);
        assert_eq!(matter2.soft.as_str(), soft);
        assert_eq!(matter2.raw(), raw);

        // Test TBD0S code with special soft value and non-empty raw
        // let code = mtr_dex::TBD0S;
        // let soft = "TG";
        // let raw = b"uvwx";
        // let qb64 = "1__-TGB1dnd4";
        //
        // let matter = BaseMatter::from_soft_and_code(soft, code).unwrap();
        // assert_eq!(matter.code(), code);
        // assert_eq!(matter.soft, soft);
        // assert_eq!(matter.raw(), b"");
        // assert_eq!(matter.qb64(), qb64);
        // assert!(matter.is_special());
        //
        // let matter2 = BaseMatter::from_qb64(qb64).unwrap();
        // assert_eq!(matter2.code(), code);
        // assert_eq!(matter2.soft, soft);
        // assert_eq!(matter2.raw(), raw);
    }
}
