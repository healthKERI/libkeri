pub mod siger;

use std::any::Any;
use std::collections::HashMap;
use crate::cesr::{b64_to_int, code_b2_to_b64, code_b64_to_b2, decode_b64, encode_b64, int_to_b64, nab_sextets, Parsable};
use crate::errors::MatterError;
use std::str;
use num_bigint::BigUint;
use crate::Matter;

#[allow(dead_code)]
pub mod idr_dex {
    use once_cell::sync::Lazy;
    use std::collections::HashMap;

    /// IndexerCodex is codex hard (stable) part of all indexer derivation codes.
    ///
    /// Codes indicate which list of keys, current and/or prior next, index is for:
    ///
    ///     _Sig:           Indices in code may appear in both current signing and
    ///                     prior next key lists when event has both current and prior
    ///                     next key lists. Two character code table has only one index
    ///                     so must be the same for both lists. Other index if for
    ///                     prior next.
    ///                     The indices may be different in those code tables which
    ///                     have two sets of indices.
    ///
    ///     _Crt_Sig:       Index in code for current signing key list only.
    ///
    ///     _Big_:          Big index values
    ///
    ///
    /// Only provide defined codes.
    /// Undefined are left out so that inclusion(exclusion) via 'in' operator works.

    pub const ED25519_SIG: &str = "A";  // Ed25519 sig appears same in both lists if any.
    pub const ED25519_CRT_SIG: &str = "B";  // Ed25519 sig appears in current list only.
    pub const ECDSA_256K1_SIG: &str = "C";  // ECDSA secp256k1 sig appears same in both lists if any.
    pub const ECDSA_256K1_CRT_SIG: &str = "D";  // ECDSA secp256k1 sig appears in current list.
    pub const ECDSA_256R1_SIG: &str = "E";  // ECDSA secp256r1 sig appears same in both lists if any.
    pub const ECDSA_256R1_CRT_SIG: &str = "F";  // ECDSA secp256r1 sig appears in current list.
    pub const ED448_SIG: &str = "0A";  // Ed448 signature appears in both lists.
    pub const ED448_CRT_SIG: &str = "0B";  // Ed448 signature appears in current list only.
    pub const ED25519_BIG_SIG: &str = "2A";  // Ed25519 sig appears in both lists.
    pub const ED25519_BIG_CRT_SIG: &str = "2B";  // Ed25519 sig appears in current list only.
    pub const ECDSA_256K1_BIG_SIG: &str = "2C";  // ECDSA secp256k1 sig appears in both lists.
    pub const ECDSA_256K1_BIG_CRT_SIG: &str = "2D";  // ECDSA secp256k1 sig appears in current list only.
    pub const ECDSA_256R1_BIG_SIG: &str = "2E";  // ECDSA secp256r1 sig appears in both lists.
    pub const ECDSA_256R1_BIG_CRT_SIG: &str = "2F";  // ECDSA secp256r1 sig appears in current list only.
    pub const ED448_BIG_SIG: &str = "3A";  // Ed448 signature appears in both lists.
    pub const ED448_BIG_CRT_SIG: &str = "3B";  // Ed448 signature appears in current list only.
    pub const TBD0: &str = "0z";  // Test of Var len label L=N*4 <= 4095 char quadlets includes code
    pub const TBD1: &str = "1z";  // Test of index sig lead 1
    pub const TBD4: &str = "4z";  // Test of index sig lead 1 big

    // Create a HashMap from name to value
    pub static MAP: Lazy<HashMap<&'static str, &'static str>> = Lazy::new(|| {
        let mut map = HashMap::new();
        map.insert("ED25519_SIG", ED25519_SIG);
        map.insert("ED25519_CRT_SIG", ED25519_CRT_SIG);
        map.insert("ECDSA_256K1_SIG", ECDSA_256K1_SIG);
        map.insert("ECDSA_256K1_CRT_SIG", ECDSA_256K1_CRT_SIG);
        map.insert("ECDSA_256R1_SIG", ECDSA_256R1_SIG);
        map.insert("ECDSA_256R1_CRT_SIG", ECDSA_256R1_CRT_SIG);
        map.insert("ED448_SIG", ED448_SIG);
        map.insert("ED448_CRT_SIG", ED448_CRT_SIG);
        map.insert("ED25519_BIG_SIG", ED25519_BIG_SIG);
        map.insert("ED25519_BIG_CRT_SIG", ED25519_BIG_CRT_SIG);
        map.insert("ECDSA_256K1_BIG_SIG", ECDSA_256K1_BIG_SIG);
        map.insert("ECDSA_256K1_BIG_CRT_SIG", ECDSA_256K1_BIG_CRT_SIG);
        map.insert("ECDSA_256R1_BIG_SIG", ECDSA_256R1_BIG_SIG);
        map.insert("ECDSA_256R1_BIG_CRT_SIG", ECDSA_256R1_BIG_CRT_SIG);
        map.insert("ED448_BIG_SIG", ED448_BIG_SIG);
        map.insert("ED448_BIG_CRT_SIG", ED448_BIG_CRT_SIG);
        map.insert("TBD0", TBD0);
        map.insert("TBD1", TBD1);
        map.insert("TBD4", TBD4);
        map
    });

    // Create an array of all constant values
    pub static VALUES: [&'static str; 19] = [
        ED25519_SIG,
        ED25519_CRT_SIG,
        ECDSA_256K1_SIG,
        ECDSA_256K1_CRT_SIG,
        ECDSA_256R1_SIG,
        ECDSA_256R1_CRT_SIG,
        ED448_SIG,
        ED448_CRT_SIG,
        ED25519_BIG_SIG,
        ED25519_BIG_CRT_SIG,
        ECDSA_256K1_BIG_SIG,
        ECDSA_256K1_BIG_CRT_SIG,
        ECDSA_256R1_BIG_SIG,
        ECDSA_256R1_BIG_CRT_SIG,
        ED448_BIG_SIG,
        ED448_BIG_CRT_SIG,
        TBD0,
        TBD1,
        TBD4,
    ];
}


#[allow(dead_code)]
pub mod idx_sig_dex {
    use once_cell::sync::Lazy;
    use std::collections::HashMap;

    /// IndexedSigCodex is codex all indexed signature derivation codes.
    ///
    /// Only provide defined codes.
    /// Undefined are left out so that inclusion(exclusion) via 'in' operator works.

    pub const ED25519_SIG: &str = "A";  // Ed25519 sig appears same in both lists if any.
    pub const ED25519_CRT_SIG: &str = "B";  // Ed25519 sig appears in current list only.
    pub const ECDSA_256K1_SIG: &str = "C";  // ECDSA secp256k1 sig appears same in both lists if any.
    pub const ECDSA_256K1_CRT_SIG: &str = "D";  // ECDSA secp256k1 sig appears in current list.
    pub const ECDSA_256R1_SIG: &str = "E";  // ECDSA secp256r1 sig appears same in both lists if any.
    pub const ECDSA_256R1_CRT_SIG: &str = "F";  // ECDSA secp256r1 sig appears in current list.
    pub const ED448_SIG: &str = "0A";  // Ed448 signature appears in both lists.
    pub const ED448_CRT_SIG: &str = "0B";  // Ed448 signature appears in current list only.
    pub const ED25519_BIG_SIG: &str = "2A";  // Ed25519 sig appears in both lists.
    pub const ED25519_BIG_CRT_SIG: &str = "2B";  // Ed25519 sig appears in current list only.
    pub const ECDSA_256K1_BIG_SIG: &str = "2C";  // ECDSA secp256k1 sig appears in both lists.
    pub const ECDSA_256K1_BIG_CRT_SIG: &str = "2D";  // ECDSA secp256k1 sig appears in current list only.
    pub const ECDSA_256R1_BIG_SIG: &str = "2E";  // ECDSA secp256r1 sig appears in both lists.
    pub const ECDSA_256R1_BIG_CRT_SIG: &str = "2F";  // ECDSA secp256r1 sig appears in current list only.
    pub const ED448_BIG_SIG: &str = "3A";  // Ed448 signature appears in both lists.
    pub const ED448_BIG_CRT_SIG: &str = "3B";  // Ed448 signature appears in current list only.

    // Create a HashMap from name to value
    pub static MAP: Lazy<HashMap<&'static str, &'static str>> = Lazy::new(|| {
        let mut map = HashMap::new();
        map.insert("ED25519_SIG", ED25519_SIG);
        map.insert("ED25519_CRT_SIG", ED25519_CRT_SIG);
        map.insert("ECDSA_256K1_SIG", ECDSA_256K1_SIG);
        map.insert("ECDSA_256K1_CRT_SIG", ECDSA_256K1_CRT_SIG);
        map.insert("ECDSA_256R1_SIG", ECDSA_256R1_SIG);
        map.insert("ECDSA_256R1_CRT_SIG", ECDSA_256R1_CRT_SIG);
        map.insert("ED448_SIG", ED448_SIG);
        map.insert("ED448_CRT_SIG", ED448_CRT_SIG);
        map.insert("ED25519_BIG_SIG", ED25519_BIG_SIG);
        map.insert("ED25519_BIG_CRT_SIG", ED25519_BIG_CRT_SIG);
        map.insert("ECDSA_256K1_BIG_SIG", ECDSA_256K1_BIG_SIG);
        map.insert("ECDSA_256K1_BIG_CRT_SIG", ECDSA_256K1_BIG_CRT_SIG);
        map.insert("ECDSA_256R1_BIG_SIG", ECDSA_256R1_BIG_SIG);
        map.insert("ECDSA_256R1_BIG_CRT_SIG", ECDSA_256R1_BIG_CRT_SIG);
        map.insert("ED448_BIG_SIG", ED448_BIG_SIG);
        map.insert("ED448_BIG_CRT_SIG", ED448_BIG_CRT_SIG);
        map
    });

    // Create an array of all constant values
    pub static TUPLE: [&'static str; 16] = [
        ED25519_SIG,
        ED25519_CRT_SIG,
        ECDSA_256K1_SIG,
        ECDSA_256K1_CRT_SIG,
        ECDSA_256R1_SIG,
        ECDSA_256R1_CRT_SIG,
        ED448_SIG,
        ED448_CRT_SIG,
        ED25519_BIG_SIG,
        ED25519_BIG_CRT_SIG,
        ECDSA_256K1_BIG_SIG,
        ECDSA_256K1_BIG_CRT_SIG,
        ECDSA_256R1_BIG_SIG,
        ECDSA_256R1_BIG_CRT_SIG,
        ED448_BIG_SIG,
        ED448_BIG_CRT_SIG,
    ];
}


#[allow(dead_code)]
pub mod idx_crt_sig_dex {
    use once_cell::sync::Lazy;
    use std::collections::HashMap;

    /// IndexedCurrentSigCodex is codex indexed signature codes for current list.
    ///
    /// Only provide defined codes.
    /// Undefined are left out so that inclusion(exclusion) via 'in' operator works.

    pub const ED25519_CRT_SIG: &str = "B";  // Ed25519 sig appears in current list only.
    pub const ECDSA_256K1_CRT_SIG: &str = "D";  // ECDSA secp256k1 sig appears in current list only.
    pub const ECDSA_256R1_CRT_SIG: &str = "F";  // ECDSA secp256r1 sig appears in current list.
    pub const ED448_CRT_SIG: &str = "0B";  // Ed448 signature appears in current list only.
    pub const ED25519_BIG_CRT_SIG: &str = "2B";  // Ed25519 sig appears in current list only.
    pub const ECDSA_256K1_BIG_CRT_SIG: &str = "2D";  // ECDSA secp256k1 sig appears in current list only.
    pub const ECDSA_256R1_BIG_CRT_SIG: &str = "2F";  // ECDSA secp256r1 sig appears in current list only.
    pub const ED448_BIG_CRT_SIG: &str = "3B";  // Ed448 signature appears in current list only.

    // Create a HashMap from name to value
    pub static MAP: Lazy<HashMap<&'static str, &'static str>> = Lazy::new(|| {
        let mut map = HashMap::new();
        map.insert("ED25519_CRT_SIG", ED25519_CRT_SIG);
        map.insert("ECDSA_256K1_CRT_SIG", ECDSA_256K1_CRT_SIG);
        map.insert("ECDSA_256R1_CRT_SIG", ECDSA_256R1_CRT_SIG);
        map.insert("ED448_CRT_SIG", ED448_CRT_SIG);
        map.insert("ED25519_BIG_CRT_SIG", ED25519_BIG_CRT_SIG);
        map.insert("ECDSA_256K1_BIG_CRT_SIG", ECDSA_256K1_BIG_CRT_SIG);
        map.insert("ECDSA_256R1_BIG_CRT_SIG", ECDSA_256R1_BIG_CRT_SIG);
        map.insert("ED448_BIG_CRT_SIG", ED448_BIG_CRT_SIG);
        map
    });

    // Create an array of all constant values
    pub static TUPLE: [&'static str; 8] = [
        ED25519_CRT_SIG,
        ECDSA_256K1_CRT_SIG,
        ECDSA_256R1_CRT_SIG,
        ED448_CRT_SIG,
        ED25519_BIG_CRT_SIG,
        ECDSA_256K1_BIG_CRT_SIG,
        ECDSA_256R1_BIG_CRT_SIG,
        ED448_BIG_CRT_SIG,
    ];
}

#[allow(dead_code)]
pub mod idx_bth_sig_dex {
    use once_cell::sync::Lazy;
    use std::collections::HashMap;

    /// IndexedBothSigCodex is codex indexed signature codes for both lists.
    ///
    /// Only provide defined codes.
    /// Undefined are left out so that inclusion(exclusion) via 'in' operator works.

    pub const ED25519_SIG: &str = "A";  // Ed25519 sig appears same in both lists if any.
    pub const ECDSA_256K1_SIG: &str = "C";  // ECDSA secp256k1 sig appears same in both lists if any.
    pub const ECDSA_256R1_SIG: &str = "E";  // ECDSA secp256r1 sig appears same in both lists if any.
    pub const ED448_SIG: &str = "0A";  // Ed448 signature appears in both lists.
    pub const ED25519_BIG_SIG: &str = "2A";  // Ed25519 sig appears in both listsy.
    pub const ECDSA_256K1_BIG_SIG: &str = "2C";  // ECDSA secp256k1 sig appears in both lists.
    pub const ECDSA_256R1_BIG_SIG: &str = "2E";  // ECDSA secp256r1 sig appears in both lists.
    pub const ED448_BIG_SIG: &str = "3A";  // Ed448 signature appears in both lists.

    // Create a HashMap from name to value
    pub static MAP: Lazy<HashMap<&'static str, &'static str>> = Lazy::new(|| {
        let mut map = HashMap::new();
        map.insert("ED25519_SIG", ED25519_SIG);
        map.insert("ECDSA_256K1_SIG", ECDSA_256K1_SIG);
        map.insert("ECDSA_256R1_SIG", ECDSA_256R1_SIG);
        map.insert("ED448_SIG", ED448_SIG);
        map.insert("ED25519_BIG_SIG", ED25519_BIG_SIG);
        map.insert("ECDSA_256K1_BIG_SIG", ECDSA_256K1_BIG_SIG);
        map.insert("ECDSA_256R1_BIG_SIG", ECDSA_256R1_BIG_SIG);
        map.insert("ED448_BIG_SIG", ED448_BIG_SIG);
        map
    });

    // Create an array of all constant values
    pub static TUPLE: [&'static str; 8] = [
        ED25519_SIG,
        ECDSA_256K1_SIG,
        ECDSA_256R1_SIG,
        ED448_SIG,
        ED25519_BIG_SIG,
        ECDSA_256K1_BIG_SIG,
        ECDSA_256R1_BIG_SIG,
        ED448_BIG_SIG,
    ];
}

#[derive(Clone, Copy, Debug)]
struct Xizage {
    hs: u32,  // header size
    ss: u32,  // section size
    os: u32,  // extra size
    fs: Option<u32>,  // field size
    ls: u32,  // list size
}

fn get_sizes() -> HashMap<&'static str, Xizage> {
    let mut sizes = HashMap::new();
    sizes.insert("A", Xizage { hs: 1, ss: 1, os: 0, fs: Some(88), ls: 0 });
    sizes.insert("B", Xizage { hs: 1, ss: 1, os: 0, fs: Some(88), ls: 0 });
    sizes.insert("C", Xizage { hs: 1, ss: 1, os: 0, fs: Some(88), ls: 0 });
    sizes.insert("D", Xizage { hs: 1, ss: 1, os: 0, fs: Some(88), ls: 0 });
    sizes.insert("E", Xizage { hs: 1, ss: 1, os: 0, fs: Some(88), ls: 0 });
    sizes.insert("F", Xizage { hs: 1, ss: 1, os: 0, fs: Some(88), ls: 0 });
    sizes.insert("0A", Xizage { hs: 2, ss: 2, os: 1, fs: Some(156), ls: 0 });
    sizes.insert("0B", Xizage { hs: 2, ss: 2, os: 1, fs: Some(156), ls: 0 });
    sizes.insert("2A", Xizage { hs: 2, ss: 4, os: 2, fs: Some(92), ls: 0 });
    sizes.insert("2B", Xizage { hs: 2, ss: 4, os: 2, fs: Some(92), ls: 0 });
    sizes.insert("2C", Xizage { hs: 2, ss: 4, os: 2, fs: Some(92), ls: 0 });
    sizes.insert("2D", Xizage { hs: 2, ss: 4, os: 2, fs: Some(92), ls: 0 });
    sizes.insert("2E", Xizage { hs: 2, ss: 4, os: 2, fs: Some(92), ls: 0 });
    sizes.insert("2F", Xizage { hs: 2, ss: 4, os: 2, fs: Some(92), ls: 0 });
    sizes.insert("3A", Xizage { hs: 2, ss: 6, os: 3, fs: Some(160), ls: 0 });
    sizes.insert("3B", Xizage { hs: 2, ss: 6, os: 3, fs: Some(160), ls: 0 });
    sizes.insert("0z", Xizage { hs: 2, ss: 2, os: 0, fs: None, ls: 0 });
    sizes.insert("1z", Xizage { hs: 2, ss: 2, os: 1, fs: Some(76), ls: 1 });
    sizes.insert("4z", Xizage { hs: 2, ss: 6, os: 3, fs: Some(80), ls: 1 });

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
    map.extend([(b'0', 2), (b'1', 2), (b'2', 2), (b'3', 2), (b'4', 2)]);

    map
}

/// Map of binary quadlet characters to their hardness values
/// This converts the base64 characters in the Hards map to their binary
/// representation and maps them to the same hardness values
#[allow(dead_code)]
pub fn get_bards() -> HashMap<u8, i32> {
    let hards = crate::cesr::hards();
    hards.iter().map(|(&c, &hs)| (code_b64_to_b2(c), hs)).collect()
}


///  Indexer is fully qualified cryptographic material primitive base class for
///  indexed primitives. In special cases some codes in the Index code table
///  may be of variable length (i.e. not indexed) when the full size table entry
///  is None. In that case the index is used instread as the length.
///
///  Sub classes are derivation code and key event element context specific.
pub trait Indexer: Matter {
    fn index(&self) -> u32;

    fn ondex(&self) -> Option<u32>;
}

#[derive(Debug, Clone)]
pub struct BaseIndexer {
    code: String,
    raw: Vec<u8>,
    index: u32,
    ondex: Option<u32>,
}

impl BaseIndexer {
    pub fn new(raw: Option<&[u8]>, code: Option<&str>, index: Option<u32>, ondex: Option<u32>) -> Result<Self, MatterError> {
        // -----------------------------------------------
        // The Python snippet starts with: if raw is not None:
        // so we mimic that branch.
        if let Some(raw_bytes) = raw {
            // if not code => raise EmptyMaterialError
            if code.is_none() || code.unwrap().is_empty() {
                return Err(MatterError::EmptyMaterialError(
                    "Improper initialization: need either (raw and code) or qb64b or qb64 or qb2."
                        .to_owned(),
                ));
            }
            let code_str = code.unwrap();

            // if code not in self.Sizes => raise UnexpectedCodeError
            let sizes = get_sizes();
            let (hs, ss, os, mut fs, _ls) = match sizes.get(code_str) {
                Some(s) => (s.hs, s.ss, s.os, s.fs.unwrap_or(0), s.ls),
                None => {
                    return Err(MatterError::UnexpectedCodeError(format!(
                        "Unsupported code={}",
                        code_str
                    )))
                }
            };

            let cs = hs + ss;    // combined code size
            let ms = ss.saturating_sub(os); // (ss - os)

            // if not isinstance(index, int) or index < 0 or index > (64**ms - 1):
            // In Rust, index is Option<u32>, so negative is impossible. We'll just check upper bound.
            let idx = match index {
                Some(i) => i,
                None => {
                    return Err(MatterError::InvalidVarIndexError(format!(
                        "Invalid index=None for code={}",
                        code_str
                    )))
                }
            };
            // Check idx <= (64^ms - 1).  64^ms might be large, so handle carefully if ms is big.
            // This naive approach uses 64u64.pow(ms), but real code might need big-int if ms can be large.
            let max_index = 64u64
                .checked_pow(ms)
                .unwrap_or(0) // If overflow, treat as error or 0
                .saturating_sub(1);
            if (idx as u64) > max_index {
                return Err(MatterError::InvalidVarIndexError(format!(
                    "Invalid index={} for code={}",
                    idx, code_str
                )));
            }

            let mut on = ondex; // We'll possibly modify ondex below.

            // if isinstance(ondex, int) and os != 0 => check bounds
            if let Some(on_val) = on {
                let max_ondex = 64u64
                    .checked_pow(os)
                    .unwrap_or(0)
                    .saturating_sub(1);
                if os != 0 && (on_val as u64) > max_ondex {
                    return Err(MatterError::InvalidVarIndexError(format!(
                        "Invalid ondex={} for code={}",
                        on_val, code_str
                    )));
                }
            }

            // if code in IdxCrtSigDex and ondex is not None => raise error
            if idx_crt_sig_dex::TUPLE.contains(&code_str) && ondex.is_some() {
                return Err(MatterError::InvalidVarIndexError(format!(
                    "Non None ondex={:?} for code={}",
                    on, code_str
                )));
            }

            // if code in IdxBthSigDex => handle default or matching
            if idx_bth_sig_dex::TUPLE.contains(&code_str) {
                if on.is_none() {
                    // default: ondex = index
                    on = Some(idx);
                } else {
                    // if ondex != index and os == 0 => raise error
                    let on_val = on.unwrap();
                    if on_val != idx && os == 0 {
                        return Err(MatterError::InvalidVarIndexError(format!(
                            "Non-matching ondex={} and index={} for code={}",
                            on_val, idx, code_str
                        )));
                    }
                }
            }

            // if not fs => compute fs.  (in Python: `if not fs:`)
            if fs == 0 {
                // if cs % 4 => raise error
                if cs % 4 != 0 {
                    return Err(MatterError::InvalidCodeSizeError(format!(
                        "Whole code size not multiple of 4 for variable-length material. cs={}",
                        cs
                    )));
                }
                // if os != 0 => raise error
                if os != 0 {
                    return Err(MatterError::InvalidCodeSizeError(format!(
                        "Non-zero other index size for variable-length material. os={}",
                        os
                    )));
                }
                // fs = (index * 4) + cs
                fs = (idx * 4) + cs;
            }

            // rawsize = (fs - cs) * 3 // 4
            let raw_size = ((fs.saturating_sub(cs)) * 3) / 4;
            // raw = raw[:rawsize], must not be shorter
            if raw_bytes.len() < raw_size as usize {
                return Err(MatterError::RawMaterialError(format!(
                    "Not enough raw bytes for code={} and index={}, expected {}, got {}",
                    code_str,
                    idx,
                    raw_size,
                    raw_bytes.len()
                )));
            }
            let raw_bytes = &raw_bytes[..raw_size as usize];

            // Final creation
            Ok(Self {
                code: code_str.to_string(),
                index: idx,
                ondex: on,
                raw: raw_bytes.to_vec(), // .to_vec() creates an owned Vec<u8>
            })
        } else {
            // The provided Python snippet is for the “raw is not None” branch only.
            // In a real codebase, you might handle other initialization paths here
            // (e.g. using qb64, qb64b, qb2). For now, we’ll just error out:
            Err(MatterError::EmptyMaterialError(
                "No raw provided; not handling qb64 or qb2 in this snippet.".to_owned(),
            ))
        }
    }

    pub fn from_raw(raw: Option<&[u8]>) -> Result<Self, MatterError> {
        BaseIndexer::new(raw, Some(idr_dex::ED25519_SIG), Some(0), None)
    }

    /// Extracts code, index, and raw from qualified base64 bytes (qb64b)
    ///
    /// # Parameters
    /// * `qb64b` - A slice of bytes containing the qualified base64 data
    ///
    /// # Returns
    /// * `Result<Self, MatterError>` - A new BaseIndexer instance or an error
    pub fn from_qb64(qb64b: &str) -> Result<Self, MatterError> {
        // Check if qb64b is empty
        if qb64b.is_empty() {
            return Err(MatterError::ShortageError("Empty material.".to_string()));
        }

        // Extract first character (code selector)
        let first = &qb64b[..1];

        // Check if first character is in HARDS
        let hards = hards();
        if !hards.contains_key(&first.bytes().next().unwrap_or(b'A')) {
            return if first.starts_with('-') {
                Err(MatterError::UnexpectedCountCodeError(
                    "Unexpected count code start while extracting Indexer.".to_string(),
                ))
            } else if first.starts_with('_') {
                Err(MatterError::UnexpectedOpCodeError(
                    "Unexpected op code start while extracting Indexer.".to_string(),
                ))
            } else {
                Err(MatterError::UnexpectedCodeError(
                    format!("Unsupported code start char={}.", first),
                ))
            }
        }

        // Get hard code size
        let hs = *hards.get(&first.bytes().next().unwrap_or(b'A')).unwrap();

        // Check if we have enough bytes
        if qb64b.len() < hs as usize {
            return Err(MatterError::ShortageError(
                format!("Need {} more characters.", hs - qb64b.len() as i32),
            ));
        }

        // Get hard code
        let hard = &qb64b[..hs as usize];

        // Check if hard code is supported
        let sizes = get_sizes();
        if !sizes.contains_key(hard) {
            return Err(MatterError::UnexpectedCodeError(
                format!("Unsupported code ={}.", hard),
            ));
        }

        // Get sizes
        let s = *sizes.get(hard).unwrap();
        let (hs, ss, os, mut fs, ls) = (s.hs, s.ss, s.os, s.fs.unwrap_or(0), s.ls);
        let cs = hs + ss; // both hard + soft code size
        let ms = ss - os;  // main index size

        // Check if we have enough bytes for code
        if qb64b.len() < cs as usize {
            return Err(MatterError::ShortageError(
                format!("Need {} more characters.", cs - qb64b.len() as u32),
            ));
        }

        // Extract index/size chars and convert to integer
        let index_slice = &qb64b[hs as usize..(hs + ms) as usize];
        let index_str = index_slice;
        let index = b64_to_int(index_str);

        // Extract ondex chars
        let ondex_slice = &qb64b[(hs + ms) as usize..(hs + ms + os) as usize];
        let ondex_str = ondex_slice;

        // Handle ondex based on code type
        let ondex = if idx_crt_sig_dex::TUPLE.contains(&hard) {
            // If current sig, ondex from code must be 0
            let ondex_val = if os > 0 { Some(b64_to_int(ondex_str)) } else { None };

            if let Some(ondex) = ondex_val {
                if ondex > 0 {
                    return Err(MatterError::ValueError(
                        format!("Invalid ondex={} for code={}.", ondex, hard),
                    ));
                }
            }

            None // Set to None when current only
        } else {
            // Otherwise, ondex is either from the string or equals index
            if os > 0 {
                Some(b64_to_int(ondex_str))
            } else {
                Some(index)
            }
        };

        // Handle variable length codes (when fs is None/0)
        if fs == 0 {
            // Compute fs from index
            if cs % 4 != 0 {
                return Err(MatterError::ValidationError(
                    format!("Whole code size not multiple of 4 for variable length material. cs={}.", cs),
                ));
            }

            if os != 0 {
                return Err(MatterError::ValidationError(
                    format!("Non-zero other index size for variable length material. os={}.", os),
                ));
            }

            fs = (index * 4) + cs;
        }

        // Check if we have enough bytes for full material
        if qb64b.len() < fs as usize {
            return Err(MatterError::ShortageError(
                format!("Need {} more chars.", fs - qb64b.len() as u32),
            ));
        }

        // Extract the fully qualified code plus material
        let qb64b = &qb64b[..fs as usize];

        // Handle padding and decoding
        let ps = cs % 4; // code pad size
        let pbs = 2 * (if ps > 0 { ps } else { ls }); // pad bit size in bits

        let raw = if ps > 0 {
            // If ps, replace pre-code with prepad chars of zero
            let base = "A".repeat(ps as usize) + &qb64b[cs as usize..]; // prepad ps 'A's to B64 of (lead + raw)
            // Decode base to leave prepadded raw
            let paw = decode_b64(&base)?;

            // Check for non-zeroed pad bits
            let pi = bytes_to_int(&paw[..ps as usize]);
            if pi & ((1 << pbs) - 1) != 0 {
                return Err(MatterError::ValueError(
                    format!("Non zeroed prepad bits = {:06b} in {}.",
                            pi & ((1 << pbs) - 1),
                            &qb64b[cs as usize..cs as usize + 1]
                    ),
                ));
            }

            // Strip off ps prepad bytes
            paw[ps as usize..].to_vec()
        } else {
            // If not ps, strip off code leaving lead chars if any and value
            let base = &qb64b[cs as usize..];

            // Decode lead chars + val leaving lead bytes + raw bytes
            let paw = decode_b64(String::from(base).as_str())?;

            // Check for non-zeroed lead bytes
            if ls > 0 {
                let li = bytes_to_int(&paw[..ls as usize]);
                if li != 0 {
                    return if ls == 1 {
                        Err(MatterError::ValueError(
                            format!("Non zeroed lead byte = 0x{:02x}.", li),
                        ))
                    } else {
                        Err(MatterError::ValueError(
                            format!("Non zeroed lead bytes = 0x{:04x}.", li),
                        ))
                    }
                }
            }

            // Strip off ls lead bytes
            paw[ls as usize..].to_vec()
        };

        // Verify exact lengths
        let expected_raw_len = (qb64b.len() - cs as usize) * 3 / 4;
        if raw.len() != expected_raw_len {
            return Err(MatterError::ConversionError(
                format!("Improperly qualified material = {:?}", qb64b),
            ));
        }

        // Construct the BaseIndexer
        Ok(BaseIndexer {
            code: hard.to_string(),
            index,
            ondex,
            raw,
        })
    }

    pub fn bexfil(qb2: &[u8]) -> Result<Self, MatterError> {
        // Empty need more bytes
        if qb2.is_empty() {
            return Err(MatterError::ShortageError("Empty material, Need more bytes.".to_string()));
        }

        // Extract first sextet as code selector
        let first = nab_sextets(qb2, 1)?;

        let bards = get_bards();
        if !bards.contains_key(&first[0]) {
            return if first[0] == 0xf8 {  // b64ToB2('-')
                Err(MatterError::UnexpectedCountCodeError(
                    "Unexpected count code start while extracting Matter.".to_string()
                ))
            } else if first[0] == 0xfc {  // b64ToB2('_')
                Err(MatterError::UnexpectedOpCodeError(
                    "Unexpected op code start while extracting Matter.".to_string()
                ))
            } else {
                Err(MatterError::UnexpectedCodeError(
                    format!("Unsupported code start sextet={:?}.", first)
                ))
            }
        }

        // Get code hard size equivalent sextets
        let hs = *bards.get(&first[0]).unwrap();

        // bhs is min bytes to hold hs sextets
        let bhs = ((hs * 3) as f64 / 4.0).ceil() as usize;

        // Need more bytes
        if qb2.len() < bhs {
            return Err(MatterError::ShortageError(
                format!("Need {} more bytes.", bhs - qb2.len())
            ));
        }

        // Extract and convert hard part of code
        let hard = code_b2_to_b64(qb2, hs as usize)?;

        let sizes = get_sizes();
        if !sizes.contains_key(hard.as_str()) {
            return Err(MatterError::UnexpectedCodeError(
                format!("Unsupported code={}.", hard)
            ));
        }

        let size = sizes.get(hard.as_str()).unwrap();
        let (hs, ss, os, fs, ls) = (size.hs, size.ss, size.os, size.fs, size.ls);

        let cs = hs + ss;  // Both hs and ss
        let ms = ss - os;

        // bcs is min bytes to hold cs sextets
        let bcs = ((cs * 3) as f64 / 4.0).ceil() as usize;

        // Need more bytes
        if qb2.len() < bcs {
            return Err(MatterError::ShortageError(
                format!("Need {} more bytes.", bcs - qb2.len())
            ));
        }

        // Extract and convert both hard and soft part of code
        let both = code_b2_to_b64(qb2, cs as usize)?;

        // Compute index
        let index = b64_to_int(&both[hs as usize..(hs + ms) as usize]);

        // Determine ondex
        let ondex = if os > 0 {
            let computed_ondex = b64_to_int(&both[(hs + ms) as usize..(hs + ms + os) as usize]);

            if idx_crt_sig_dex::TUPLE.contains(&hard.as_str()) {
                // If current sig then ondex from code must be 0
                if computed_ondex != 0 {
                    return Err(MatterError::ValueError(
                        format!("Invalid ondex={} for code={}.", computed_ondex, hard)
                    ));
                }
                None
            } else {
                Some(computed_ondex)
            }
        } else if idx_crt_sig_dex::TUPLE.contains(&hard.as_str()) {
            None
        } else {
            Some(index)
        };

        // Determine final size (fs)
        let fs_value = match fs {
            Some(fs_val) => fs_val as usize,
            None => {
                // Compute fs from size chars in ss part of code
                if cs % 4 != 0 {
                    return Err(MatterError::ValidationError(
                        format!("Whole code size not multiple of 4 for variable length material. cs={}.", cs)
                    ));
                }

                if os != 0 {
                    return Err(MatterError::ValidationError(
                        format!("Non-zero other index size for variable length material. os={}.", os)
                    ));
                }

                (index as usize * 4) + cs as usize
            }
        };

        // bfs is min bytes to hold fs sextets
        let bfs = ((fs_value * 3) as f64 / 4.0).ceil() as usize;

        // Need more bytes
        if qb2.len() < bfs {
            return Err(MatterError::ShortageError(
                format!("Need {} more bytes.", bfs - qb2.len())
            ));
        }

        // Extract qb2 fully qualified primitive code plus material
        let qb2 = &qb2[..bfs];

        // Check for non-zeroed prepad bits or lead bytes
        let ps = cs % 4;  // Code pad size ps = cs mod 4
        let pbs = 2 * if ps > 0 { ps } else { ls };  // Pad bit size in bits

        if ps > 0 {
            // Convert last byte of code bytes in which are pad bits to int
            let pi = qb2[bcs - 1] as usize;

            if pi & ((1 << pbs) - 1) != 0 {  // Masked pad bits non-zero
                return Err(MatterError::ValueError(
                    format!("Non zeroed pad bits = {:08b} in 0x{:02x}.", pi & ((1 << pbs) - 1), pi)
                ));
            }
        } else {
            // Check lead bytes
            let mut li = 0;
            for i in 0..ls as usize {
                li = (li << 8) | (qb2[bcs + i] as usize);
            }

            if li != 0 {  // Pre pad lead bytes must be zero
                return if ls == 1 {
                    Err(MatterError::ValueError(
                        format!("Non zeroed lead byte = 0x{:02x}.", li)
                    ))
                } else {
                    Err(MatterError::ValueError(
                        format!("Non zeroed lead bytes = 0x{:02x}.", li)
                    ))
                }
            }
        }

        // Strip code and leader bytes from qb2 to get raw
        let raw = &qb2[(bcs + ls as usize)..];

        if raw.len() != (qb2.len() - bcs - ls as usize) {  // Exact lengths
            return Err(MatterError::ConversionError(
                format!("Improperly qualified material = {:?}", qb2)
            ));
        }
        Ok(BaseIndexer {
            code: hard.to_string(),
            index,
            ondex,
            raw: Vec::from(raw),
        })
    }


    fn infil(&self) -> Result<String, MatterError> {
        let code = self.code();
        let index = self.index();
        let ondex = self.ondex().unwrap_or(0);
        let raw = self.raw();

        // Calculate padding size: (3 - (len(raw) % 3)) % 3
        let ps = (3 - (raw.len() % 3)) % 3;

        // Get size parameters from the SIZES map
        let sizes = get_sizes();
        let size = sizes.get(code).unwrap();
        let (hs, ss, os, fs, ls) = (size.hs, size.ss, size.os, size.fs.unwrap_or(0), size.ls);

        let cs = hs + ss;
        let ms = ss - os;

        let fs = if fs == 0 {
            // Compute fs from index
            if cs % 4 != 0 {
                return Err(MatterError::InvalidCodeSize(
                    format!("Whole code size not multiple of 4 for variable length material. cs={}", cs)
                ));
            }

            if os != 0 {
                return Err(MatterError::InvalidCodeSize(
                    format!("Non-zero other index size for variable length material. os={}", os)
                ));
            }

            (index as usize * 4) + cs as usize
        } else {
            fs as usize
        };

        // Validate index and ondex
        let max_index = 64u64.pow(ms) - 1;
        if index as u64 > max_index {
            return Err(MatterError::InvalidVarIndex(
                format!("Invalid index={} for code={}", index, code)
            ));
        }

        if os > 0 {
            let max_ondex = 64u64.pow(os) - 1;
            if ondex as u64 > max_ondex {
                return Err(MatterError::InvalidVarIndex(
                    format!("Invalid ondex={} for os={} and code={}", ondex, os, code)
                ));
            }
        }

        // Create "both" - hard code + converted index + converted ondex
        let both = format!("{}{}{}",
                           code,
                           int_to_b64(index, ms as usize),
                           int_to_b64(ondex, os as usize)
        );

        // Check valid code size
        if both.len() != cs as usize {
            return Err(MatterError::InvalidCodeSize(
                format!("Mismatch code size = {} with table = {}", cs, both.len())
            ));
        }

        // Check adjusted pad given lead bytes
        if (cs % 4) != (ps - ls as usize) as u32 {
            return Err(MatterError::InvalidCodeSize(
                format!("Invalid code={} for converted raw pad size={}", both, ps)
            ));
        }

        // Prepend pad bytes, convert, then replace pad chars with full derivation code including index
        let mut pad_bytes = vec![0u8; ps];
        pad_bytes.extend_from_slice(raw);

        let encoded = encode_b64(&pad_bytes);
        let full = format!("{}{}", both, encoded.chars().skip(ps - ls as usize).collect::<String>());

        // Check final size
        if full.len() != fs {
            return Err(MatterError::InvalidCodeSize(
                format!("Invalid code={} for raw size={}", both, raw.len())
            ));
        }

        Ok(full)
    }

    pub fn binfil(&self) -> Result<Vec<u8>, MatterError> {
        let code = self.code();
        let index = self.index();
        let ondex = self.ondex().unwrap_or(0);
        let raw = self.raw();

        // Calculate padding size: (3 - (len(raw) % 3)) % 3
        let ps = (3 - (raw.len() % 3)) % 3;

        // Get size parameters from the SIZES map
        let sizes = get_sizes();
        let size = sizes.get(code).unwrap();
        let (hs, ss, os, fs, ls) = (size.hs, size.ss, size.os, size.fs.unwrap_or(0), size.ls);
        let cs = hs + ss;
        let ms = ss - os;

        // Validate index and ondex
        let max_index = 64u64.pow(ss) - 1;
        if index as u64 > max_index {
            return Err(MatterError::InvalidVarIndex(
                format!("Invalid index={} for code={}", index, code)
            ));
        }

        if os > 0 {
            let max_ondex = 64u64.pow(os) - 1;
            if ondex as u64 > max_ondex {
                return Err(MatterError::InvalidVarIndex(
                    format!("Invalid ondex={} for os={} and code={}", ondex, os, code)
                ));
            }
        }

        let fs = if fs == 0 {
            // Compute fs from index
            if cs % 4 != 0 {
                return Err(MatterError::InvalidCodeSize(
                    format!("Whole code size not multiple of 4 for variable length material. cs={}", cs)
                ));
            }

            if os != 0 {
                return Err(MatterError::InvalidCodeSize(
                    format!("Non-zero other index size for variable length material. os={}", os)
                ));
            }

            (index as usize * 4) + cs as usize
        } else {
            fs  as usize
        };

        // Create "both" - hard code + converted index + converted ondex
        let both = format!("{}{}{}",
                           code,
                           int_to_b64(index, ms as usize),
                           int_to_b64(ondex, os as usize)
        );

        // Check valid code size
        if both.len() != cs as usize{
            return Err(MatterError::InvalidCodeSize(
                format!("Mismatch code size = {} with table = {}", cs, both.len())
            ));
        }

        // Check adjusted pad given lead bytes
        if (cs % 4) != (ps - ls as usize) as u32 {
            return Err(MatterError::InvalidCodeSize(
                format!("Invalid code={} for converted raw pad size={}", both, ps)
            ));
        }

        // Number of b2 bytes to hold b64 code + index
        let n = sceil(cs as usize * 3, 4);

        // Convert code both to right align b2 int then left shift in pad bits
        // then convert to bytes
        let b64_int = b64_to_int(&both);
        let shifted = b64_int << (2 * (ps - ls as usize));

        // Convert to big-endian bytes with the correct length
        let bcode = int_to_bytes(BigUint::from(shifted), n);

        // Create the full binary representation
        let mut full = bcode;
        full.extend(vec![0u8; ls as usize]);
        full.extend_from_slice(raw);

        // Check the binary full size
        let bfs = full.len();
        if bfs % 3 != 0 || (bfs * 4 / 3) != fs {
            return Err(MatterError::InvalidCodeSize(
                format!("Invalid code={} for raw size={}", both, raw.len())
            ));
        }

        Ok(full)
    }
}

impl Parsable for BaseIndexer {
    fn from_qb64b(data: &mut Vec<u8>, strip: Option<bool>) -> Result<Self, MatterError> {
        let qb64b = data.as_slice();
        let qb64 = str::from_utf8(qb64b).ok();
        let idx = BaseIndexer::from_qb64(qb64.unwrap_or(""))?;
        if strip.unwrap_or(false) {
            let fs = idx.full_size();
            data.drain(..fs);
        }
        Ok(idx)
    }

    /// Creates a new BaseMatter from qb2 bytes
    fn from_qb2(data: &mut Vec<u8>, strip: Option<bool>) -> Result<Self, MatterError> {
        let qb2 = data.as_slice();
        let idx = BaseIndexer::bexfil(qb2)?;
        if strip.unwrap_or(false) {
            let fs = idx.full_size();
            data.drain(..fs);
        }
        Ok(idx)
    }
}


fn sceil(a: usize, b: usize) -> usize {
    (a + b - 1) / b
}

// Helper function to convert bytes to integer (big-endian)
fn bytes_to_int(bytes: &[u8]) -> u32 {
    let mut result: u32 = 0;
    for &byte in bytes {
        result = (result << 8) | (byte as u32);
    }
    result
}

/// Convert a big integer to bytes with specified length
fn int_to_bytes(value: BigUint, length: usize) -> Vec<u8> {
    let bytes = value.to_bytes_be();

    if bytes.len() >= length {
        return bytes;
    }

    // Pad with leading zeros to reach the required length
    let mut result = vec![0; length - bytes.len()];
    result.extend_from_slice(&bytes);
    result
}

impl Matter for BaseIndexer {
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
        let result = self.qb64();
        result.as_bytes().to_vec()
    }

    fn qb2(&self) -> Vec<u8> {
        let result = self.binfil();
        result.unwrap()
    }

    fn soft(&self) -> &str {
        ""
    }

    fn full_size(&self) -> usize {
        let sizes = get_sizes();
        let size = sizes[self.code.as_str()];
        size.fs.or_else(|| Some(0)).unwrap() as usize
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
        false
    }

    fn is_digestive(&self) -> bool {
        false
    }

    fn is_prefixive(&self) -> bool {
        false
    }

    fn is_special(&self) -> bool {
        false
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl Indexer for BaseIndexer {
    fn index(&self) -> u32 {
        self.index
    }

    fn ondex(&self) -> Option<u32> {
        self.ondex
    }
}

/// Returns expected raw size in bytes for a given code.
/// Not applicable to codes with fs = None
pub fn raw_size(code: &str) -> Result<usize, MatterError> {
    // Assuming Sizes is a HashMap or similar structure mapping codes to size tuples
    // Get the size tuple from the Sizes map
    let sizes = get_sizes();
    let size = sizes[code];

    let (hs, ss, _, fs, _) = (size.hs, size.ss, size.os, size.fs.unwrap(), size.ls);

    // Calculate and return the raw size
    // Converting to isize to avoid potential underflow in subtraction
    let fs_minus_headers = (fs as isize) - ((hs as isize) + (ss as isize));

    // Convert back to usize after calculation
    Ok(((fs_minus_headers * 3) / 4) as usize)
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::cesr::encode_b64;

    #[test]
    fn test_base_indexer_from_qb64() {
        // Create signature bytes (same as in Python test)
        let sig = [
            0x99, 0xd2, 0x3c, 0x39, 0x24, 0x24, 0x30, 0x9f, 0x6b, 0xfb, 0x18, 0xa0, 0x8c, 0x40,
            0x72, 0x12, 0x32, 0x2e, 0x6b, 0xb2, 0xc7, 0x1f, 0x70, 0x0e, 0x27, 0x6d, 0x8f, 0x40,
            0xaa, 0xa5, 0x8c, 0xc8, 0x6e, 0x85, 0xc8, 0x21, 0xf6, 0x71, 0x91, 0x70, 0xa9, 0xec,
            0xcf, 0x92, 0xaf, 0x29, 0xde, 0xca, 0xfc, 0x7f, 0x7e, 0xd7, 0x6f, 0x7c, 0x17, 0x82,
            0x1d, 0xd4, 0x3c, 0x6f, 0x22, 0x81, 0x26, 0x09
        ];

        assert_eq!(sig.len(), 64);

        // Calculate padding size
        let ps = (3 - (sig.len() % 3)) % 3;

        // Create padded signature by prepending zeros
        let mut padded_sig = vec![0u8; ps];
        padded_sig.extend_from_slice(&sig);

        // Encode to Base64
        let sig64b = encode_b64(&padded_sig);

        assert_eq!(sig64b.len(), 88);
        assert_eq!(sig64b, "AACZ0jw5JCQwn2v7GKCMQHISMi5rsscfcA4nbY9AqqWMyG6FyCH2cZFwqezPkq8p3sr8f37Xb3wXgh3UPG8igSYJ");

        // Replace prepad with code "A" plus index 0 == "A"
        let qsc = idr_dex::MAP.get("ED25519_SIG").unwrap().to_string() + &int_to_b64(0, 1);
        assert_eq!(qsc, "AA");

        // Replace prepad chars with code
        let qsig64 = qsc + &sig64b[ps..];

        assert_eq!(qsig64, "AACZ0jw5JCQwn2v7GKCMQHISMi5rsscfcA4nbY9AqqWMyG6FyCH2cZFwqezPkq8p3sr8f37Xb3wXgh3UPG8igSYJ");
        assert_eq!(qsig64.len(), 88);

        let qsig64b = qsig64.as_bytes();
        // Create expected decoded bytes for verification
        let mut qsig2b = decode_b64(&qsig64).unwrap();
        assert_eq!(qsig2b.len(), 66);

        // Expected raw bytes after decoding
        let expected_raw = [
            0x99, 0xd2, 0x3c, 0x39, 0x24, 0x24, 0x30, 0x9f, 0x6b, 0xfb, 0x18, 0xa0, 0x8c, 0x40,
            0x72, 0x12, 0x32, 0x2e, 0x6b, 0xb2, 0xc7, 0x1f, 0x70, 0x0e, 0x27, 0x6d, 0x8f, 0x40,
            0xaa, 0xa5, 0x8c, 0xc8, 0x6e, 0x85, 0xc8, 0x21, 0xf6, 0x71, 0x91, 0x70, 0xa9, 0xec,
            0xcf, 0x92, 0xaf, 0x29, 0xde, 0xca, 0xfc, 0x7f, 0x7e, 0xd7, 0x6f, 0x7c, 0x17, 0x82,
            0x1d, 0xd4, 0x3c, 0x6f, 0x22, 0x81, 0x26, 0x09
        ];

        // Test the BaseIndexer::from_qb64 method
        let indexer = BaseIndexer::from_qb64(qsig64.as_str()).expect("Failed to create BaseIndexer from qb64");

        // Assertions to verify the indexer was created correctly
        assert_eq!(indexer.raw(), &expected_raw);
        assert_eq!(indexer.code(), idr_dex::ED25519_SIG);
        assert_eq!(indexer.index(), 0);
        assert_eq!(indexer.ondex(), Some(0));

        // Test that we can recreate qb64b and qb2 (similar to _exfil and _bexfil in Python)
        let qb64b = indexer.qb64b();
        assert_eq!(qb64b, qsig64b);

        let qb2 = indexer.qb2();
        assert_eq!(&qb2, &qsig2b);

        let indexer1 = BaseIndexer::from_qb2(&mut qsig2b, None).expect("Failed to create BaseIndexer from qb2");
        assert_eq!(indexer1.raw(), &expected_raw);
        assert_eq!(indexer1.code(), idr_dex::ED25519_SIG);
        assert_eq!(indexer1.index(), 0);
        assert_eq!(indexer1.ondex(), Some(0));

        // Test initialization constructor
        let indexer = BaseIndexer {
            code: idr_dex::ED25519_SIG.to_string(),
            raw: Vec::from(sig),
            index: 5,
            ondex: Some(5),
        };

        let qsig64 = "AFCZ0jw5JCQwn2v7GKCMQHISMi5rsscfcA4nbY9AqqWMyG6FyCH2cZFwqezPkq8p3sr8f37Xb3wXgh3UPG8igSYJ";
        let qsig2b = [
            0x00, 0x50, 0x99, 0xd2, 0x3c, 0x39, 0x24, 0x24, 0x30, 0x9f, 0x6b, 0xfb, 0x18, 0xa0, 0x8c, 0x40,
            0x72, 0x12, 0x32, 0x2e, 0x6b, 0xb2, 0xc7, 0x1f, 0x70, 0x0e, 0x27, 0x6d, 0x8f, 0x40, 0xaa, 0xa5,
            0x8c, 0xc8, 0x6e, 0x85, 0xc8, 0x21, 0xf6, 0x71, 0x91, 0x70, 0xa9, 0xec, 0xcf, 0x92, 0xaf, 0x29,
            0xde, 0xca, 0xfc, 0x7f, 0x7e, 0xd7, 0x6f, 0x7c, 0x17, 0x82, 0x1d, 0xd4, 0x3c, 0x6f, 0x22, 0x81,
            0x26, 0x09
        ];
        let qsig64b = qsig64.as_bytes();

        // Verify initial properties
        assert_eq!(indexer.raw, sig);
        assert_eq!(indexer.code, idr_dex::ED25519_SIG);
        assert_eq!(indexer.index, 5);
        assert_eq!(indexer.ondex, Some(5));

        // Test qb64, qb64b, and qb2 properties
        // In a real implementation, you would call methods that generate these values
        let qb64 = indexer.qb64();
        let qb64b = indexer.qb64b();
        let qb2 = indexer.qb2();

        assert_eq!(qb64, qsig64);
        assert_eq!(qb64b, qsig64b);
        assert_eq!(qb2, qsig2b);

        // Test _exfil method (similar to the Python version)
        let indexer = BaseIndexer::from_qb64b(&mut qsig64b.to_vec(), None).expect("Failed to create BaseIndexer from qb64b");
        assert_eq!(indexer.code, idr_dex::ED25519_SIG);
        assert_eq!(indexer.raw, sig);
        assert_eq!(indexer.qb64b(), qsig64b);
        assert_eq!(indexer.qb2(), qsig2b);

        // Test with explicit ondex initialization
        let indexer = BaseIndexer {
            raw: Vec::from(sig),
            code: idr_dex::ED25519_SIG.to_string(),
            index: 5,
            ondex: Some(5),
        };

        assert_eq!(indexer.raw, sig);
        assert_eq!(indexer.code, idr_dex::ED25519_SIG);
        assert_eq!(indexer.index, 5);
        assert_eq!(indexer.ondex, Some(5));

        // In a real implementation, these would call actual methods
        let qb64 = indexer.qb64();
        let qb64b = indexer.qb64b();
        let qb2 = indexer.qb2();

        assert_eq!(qb64, qsig64);
        assert_eq!(qb64b, qsig64b);
        assert_eq!(qb2, qsig2b);

        let qb64 = "AAApXLez5eVIs6YyRXOMDMBy4cTm2GvsilrZlcMmtBbO5twLst_jjFoEyfKTWKntEtv9JPBv1DLkqg-ImDmGPM8E";
        let indexer = BaseIndexer::from_qb64(qb64).expect("Failed to create BaseIndexer from qb64b");
        assert_eq!(indexer.code, idr_dex::ED25519_SIG);
        assert_eq!(indexer.index, 0);

    }
}