mod cipher;
mod decrypter;
mod encrypter;
mod salter;
pub mod signer;

pub use cipher::Cipher;
pub use decrypter::Decrypter;
pub use encrypter::Encrypter;
pub use salter::Salter;
pub use signer::Signer;

use libsodium_sys;

/// Represents different types of signatures that can be produced by signing
#[derive(Debug, Clone)]
pub enum Sigmat {
    /// Indexed signature (Siger)
    Indexed(Siger),
    /// Non-indexed signature (Cigar)
    NonIndexed(Cigar),
}

/// Module for X25519 cipher codes for variable-sized sniffable stream plaintext
#[allow(dead_code)]
pub mod cix_var_strm_dex {
    use once_cell::sync::Lazy;
    use std::collections::HashMap;

    /// X25519 sealed box cipher bytes of sniffable stream plaintext lead size 0
    pub const X25519_CIPHER_L0: &str = "4C";
    /// X25519 sealed box cipher bytes of sniffable stream plaintext lead size 1
    pub const X25519_CIPHER_L1: &str = "5C";
    /// X25519 sealed box cipher bytes of sniffable stream plaintext lead size 2
    pub const X25519_CIPHER_L2: &str = "6C";
    /// X25519 sealed box cipher bytes of sniffable stream plaintext big lead size 0
    pub const X25519_CIPHER_BIG_L0: &str = "7AAC";
    /// X25519 sealed box cipher bytes of sniffable stream plaintext big lead size 1
    pub const X25519_CIPHER_BIG_L1: &str = "8AAC";
    /// X25519 sealed box cipher bytes of sniffable stream plaintext big lead size 2
    pub const X25519_CIPHER_BIG_L2: &str = "9AAC";

    pub static MAP: Lazy<HashMap<&'static str, &'static str>> = Lazy::new(|| {
        let mut map = HashMap::new();
        map.insert("X25519_CIPHER_L0", X25519_CIPHER_L0);
        map.insert("X25519_CIPHER_L1", X25519_CIPHER_L1);
        map.insert("X25519_CIPHER_L2", X25519_CIPHER_L2);
        map.insert("X25519_CIPHER_BIG_L0", X25519_CIPHER_BIG_L0);
        map.insert("X25519_CIPHER_BIG_L1", X25519_CIPHER_BIG_L1);
        map.insert("X25519_CIPHER_BIG_L2", X25519_CIPHER_BIG_L2);
        map
    });

    pub static TUPLE: [&'static str; 6] = [
        X25519_CIPHER_L0,
        X25519_CIPHER_L1,
        X25519_CIPHER_L2,
        X25519_CIPHER_BIG_L0,
        X25519_CIPHER_BIG_L1,
        X25519_CIPHER_BIG_L2,
    ];
}

/// Module for X25519 cipher codes for variable-sized QB64 plaintext
#[allow(dead_code)]
pub mod cix_var_qb64_dex {
    use once_cell::sync::Lazy;
    use std::collections::HashMap;

    /// X25519 sealed box cipher bytes of QB64 plaintext lead size 0
    pub const X25519_CIPHER_QB64_L0: &str = "4D";
    /// X25519 sealed box cipher bytes of QB64 plaintext lead size 1
    pub const X25519_CIPHER_QB64_L1: &str = "5D";
    /// X25519 sealed box cipher bytes of QB64 plaintext lead size 2
    pub const X25519_CIPHER_QB64_L2: &str = "6D";
    /// X25519 sealed box cipher bytes of QB64 plaintext big lead size 0
    pub const X25519_CIPHER_QB64_BIG_L0: &str = "7AAD";
    /// X25519 sealed box cipher bytes of QB64 plaintext big lead size 1
    pub const X25519_CIPHER_QB64_BIG_L1: &str = "8AAD";
    /// X25519 sealed box cipher bytes of QB64 plaintext big lead size 2
    pub const X25519_CIPHER_QB64_BIG_L2: &str = "9AAD";

    pub static MAP: Lazy<HashMap<&'static str, &'static str>> = Lazy::new(|| {
        let mut map = HashMap::new();
        map.insert("X25519_CIPHER_QB64_L0", X25519_CIPHER_QB64_L0);
        map.insert("X25519_CIPHER_QB64_L1", X25519_CIPHER_QB64_L1);
        map.insert("X25519_CIPHER_QB64_L2", X25519_CIPHER_QB64_L2);
        map.insert("X25519_CIPHER_QB64_BIG_L0", X25519_CIPHER_QB64_BIG_L0);
        map.insert("X25519_CIPHER_QB64_BIG_L1", X25519_CIPHER_QB64_BIG_L1);
        map.insert("X25519_CIPHER_QB64_BIG_L2", X25519_CIPHER_QB64_BIG_L2);
        map
    });

    pub static TUPLE: [&'static str; 6] = [
        X25519_CIPHER_QB64_L0,
        X25519_CIPHER_QB64_L1,
        X25519_CIPHER_QB64_L2,
        X25519_CIPHER_QB64_BIG_L0,
        X25519_CIPHER_QB64_BIG_L1,
        X25519_CIPHER_QB64_BIG_L2,
    ];
}

/// Module for X25519 cipher codes for fixed-sized QB64 plaintext
#[allow(dead_code)]
pub mod cix_fix_qb64_dex {
    use once_cell::sync::Lazy;
    use std::collections::HashMap;

    /// X25519 sealed box 124 char qb64 Cipher of 44 char qb64 Seed
    pub const X25519_CIPHER_SEED: &str = "P";
    /// X25519 sealed box 100 char qb64 Cipher of 24 char qb64 Salt
    pub const X25519_CIPHER_SALT: &str = "1AAH";

    pub static MAP: Lazy<HashMap<&'static str, &'static str>> = Lazy::new(|| {
        let mut map = HashMap::new();
        map.insert("X25519_CIPHER_SEED", X25519_CIPHER_SEED);
        map.insert("X25519_CIPHER_SALT", X25519_CIPHER_SALT);
        map
    });

    pub static TUPLE: [&'static str; 2] = [X25519_CIPHER_SEED, X25519_CIPHER_SALT];
}

/// Module for X25519 cipher codes for all (both fixed and variable) sizes of QB64 plaintext
#[allow(dead_code)]
pub mod cix_all_qb64_dex {
    use super::{cix_fix_qb64_dex, cix_var_qb64_dex};
    use once_cell::sync::Lazy;
    use std::collections::HashMap;

    /// X25519 sealed box 124 char qb64 Cipher of 44 char qb64 Seed
    pub const X25519_CIPHER_SEED: &str = cix_fix_qb64_dex::X25519_CIPHER_SEED;
    /// X25519 sealed box 100 char qb64 Cipher of 24 char qb64 Salt
    pub const X25519_CIPHER_SALT: &str = cix_fix_qb64_dex::X25519_CIPHER_SALT;

    /// X25519 sealed box cipher bytes of QB64 plaintext lead size 0
    pub const X25519_CIPHER_QB64_L0: &str = cix_var_qb64_dex::X25519_CIPHER_QB64_L0;
    /// X25519 sealed box cipher bytes of QB64 plaintext lead size 1
    pub const X25519_CIPHER_QB64_L1: &str = cix_var_qb64_dex::X25519_CIPHER_QB64_L1;
    /// X25519 sealed box cipher bytes of QB64 plaintext lead size 2
    pub const X25519_CIPHER_QB64_L2: &str = cix_var_qb64_dex::X25519_CIPHER_QB64_L2;
    /// X25519 sealed box cipher bytes of QB64 plaintext big lead size 0
    pub const X25519_CIPHER_QB64_BIG_L0: &str = cix_var_qb64_dex::X25519_CIPHER_QB64_BIG_L0;
    /// X25519 sealed box cipher bytes of QB64 plaintext big lead size 1
    pub const X25519_CIPHER_QB64_BIG_L1: &str = cix_var_qb64_dex::X25519_CIPHER_QB64_BIG_L1;
    /// X25519 sealed box cipher bytes of QB64 plaintext big lead size 2
    pub const X25519_CIPHER_QB64_BIG_L2: &str = cix_var_qb64_dex::X25519_CIPHER_QB64_BIG_L2;

    pub static MAP: Lazy<HashMap<&'static str, &'static str>> = Lazy::new(|| {
        let mut map = HashMap::new();
        map.insert("X25519_CIPHER_SEED", X25519_CIPHER_SEED);
        map.insert("X25519_CIPHER_SALT", X25519_CIPHER_SALT);
        map.insert("X25519_CIPHER_QB64_L0", X25519_CIPHER_QB64_L0);
        map.insert("X25519_CIPHER_QB64_L1", X25519_CIPHER_QB64_L1);
        map.insert("X25519_CIPHER_QB64_L2", X25519_CIPHER_QB64_L2);
        map.insert("X25519_CIPHER_QB64_BIG_L0", X25519_CIPHER_QB64_BIG_L0);
        map.insert("X25519_CIPHER_QB64_BIG_L1", X25519_CIPHER_QB64_BIG_L1);
        map.insert("X25519_CIPHER_QB64_BIG_L2", X25519_CIPHER_QB64_BIG_L2);
        map
    });

    pub static TUPLE: [&'static str; 8] = [
        X25519_CIPHER_SEED,
        X25519_CIPHER_SALT,
        X25519_CIPHER_QB64_L0,
        X25519_CIPHER_QB64_L1,
        X25519_CIPHER_QB64_L2,
        X25519_CIPHER_QB64_BIG_L0,
        X25519_CIPHER_QB64_BIG_L1,
        X25519_CIPHER_QB64_BIG_L2,
    ];
}

/// Module for X25519 cipher codes for variable-sized QB2 plaintext
#[allow(dead_code)]
pub mod cix_var_qb2_dex {
    use once_cell::sync::Lazy;
    use std::collections::HashMap;

    /// X25519 sealed box cipher bytes of QB2 plaintext lead size 0
    pub const X25519_CIPHER_QB2_L0: &str = "4E";
    /// X25519 sealed box cipher bytes of QB2 plaintext lead size 1
    pub const X25519_CIPHER_QB2_L1: &str = "5E";
    /// X25519 sealed box cipher bytes of QB2 plaintext lead size 2
    pub const X25519_CIPHER_QB2_L2: &str = "6E";
    /// X25519 sealed box cipher bytes of QB2 plaintext big lead size 0
    pub const X25519_CIPHER_QB2_BIG_L0: &str = "7AAE";
    /// X25519 sealed box cipher bytes of QB2 plaintext big lead size 1
    pub const X25519_CIPHER_QB2_BIG_L1: &str = "8AAE";
    /// X25519 sealed box cipher bytes of QB2 plaintext big lead size 2
    pub const X25519_CIPHER_QB2_BIG_L2: &str = "9AAE";

    pub static MAP: Lazy<HashMap<&'static str, &'static str>> = Lazy::new(|| {
        let mut map = HashMap::new();
        map.insert("X25519_CIPHER_QB2_L0", X25519_CIPHER_QB2_L0);
        map.insert("X25519_CIPHER_QB2_L1", X25519_CIPHER_QB2_L1);
        map.insert("X25519_CIPHER_QB2_L2", X25519_CIPHER_QB2_L2);
        map.insert("X25519_CIPHER_QB2_BIG_L0", X25519_CIPHER_QB2_BIG_L0);
        map.insert("X25519_CIPHER_QB2_BIG_L1", X25519_CIPHER_QB2_BIG_L1);
        map.insert("X25519_CIPHER_QB2_BIG_L2", X25519_CIPHER_QB2_BIG_L2);
        map
    });

    pub static TUPLE: [&'static str; 6] = [
        X25519_CIPHER_QB2_L0,
        X25519_CIPHER_QB2_L1,
        X25519_CIPHER_QB2_L2,
        X25519_CIPHER_QB2_BIG_L0,
        X25519_CIPHER_QB2_BIG_L1,
        X25519_CIPHER_QB2_BIG_L2,
    ];
}

/// Module for X25519 cipher codes for all variable sizes and all types of plaintext
#[allow(dead_code)]
pub mod cix_var_dex {
    use super::{cix_var_qb2_dex, cix_var_qb64_dex, cix_var_strm_dex};
    use once_cell::sync::Lazy;
    use std::collections::HashMap;

    // Stream plaintext codes
    /// X25519 sealed box cipher bytes of sniffable stream plaintext lead size 0
    pub const X25519_CIPHER_L0: &str = cix_var_strm_dex::X25519_CIPHER_L0;
    /// X25519 sealed box cipher bytes of sniffable stream plaintext lead size 1
    pub const X25519_CIPHER_L1: &str = cix_var_strm_dex::X25519_CIPHER_L1;
    /// X25519 sealed box cipher bytes of sniffable stream plaintext lead size 2
    pub const X25519_CIPHER_L2: &str = cix_var_strm_dex::X25519_CIPHER_L2;
    /// X25519 sealed box cipher bytes of sniffable stream plaintext big lead size 0
    pub const X25519_CIPHER_BIG_L0: &str = cix_var_strm_dex::X25519_CIPHER_BIG_L0;
    /// X25519 sealed box cipher bytes of sniffable stream plaintext big lead size 1
    pub const X25519_CIPHER_BIG_L1: &str = cix_var_strm_dex::X25519_CIPHER_BIG_L1;
    /// X25519 sealed box cipher bytes of sniffable stream plaintext big lead size 2
    pub const X25519_CIPHER_BIG_L2: &str = cix_var_strm_dex::X25519_CIPHER_BIG_L2;

    // QB64 plaintext codes
    /// X25519 sealed box cipher bytes of QB64 plaintext lead size 0
    pub const X25519_CIPHER_QB64_L0: &str = cix_var_qb64_dex::X25519_CIPHER_QB64_L0;
    /// X25519 sealed box cipher bytes of QB64 plaintext lead size 1
    pub const X25519_CIPHER_QB64_L1: &str = cix_var_qb64_dex::X25519_CIPHER_QB64_L1;
    /// X25519 sealed box cipher bytes of QB64 plaintext lead size 2
    pub const X25519_CIPHER_QB64_L2: &str = cix_var_qb64_dex::X25519_CIPHER_QB64_L2;
    /// X25519 sealed box cipher bytes of QB64 plaintext big lead size 0
    pub const X25519_CIPHER_QB64_BIG_L0: &str = cix_var_qb64_dex::X25519_CIPHER_QB64_BIG_L0;
    /// X25519 sealed box cipher bytes of QB64 plaintext big lead size 1
    pub const X25519_CIPHER_QB64_BIG_L1: &str = cix_var_qb64_dex::X25519_CIPHER_QB64_BIG_L1;
    /// X25519 sealed box cipher bytes of QB64 plaintext big lead size 2
    pub const X25519_CIPHER_QB64_BIG_L2: &str = cix_var_qb64_dex::X25519_CIPHER_QB64_BIG_L2;

    // QB2 plaintext codes
    /// X25519 sealed box cipher bytes of QB2 plaintext lead size 0
    pub const X25519_CIPHER_QB2_L0: &str = cix_var_qb2_dex::X25519_CIPHER_QB2_L0;
    /// X25519 sealed box cipher bytes of QB2 plaintext lead size 1
    pub const X25519_CIPHER_QB2_L1: &str = cix_var_qb2_dex::X25519_CIPHER_QB2_L1;
    /// X25519 sealed box cipher bytes of QB2 plaintext lead size 2
    pub const X25519_CIPHER_QB2_L2: &str = cix_var_qb2_dex::X25519_CIPHER_QB2_L2;
    /// X25519 sealed box cipher bytes of QB2 plaintext big lead size 0
    pub const X25519_CIPHER_QB2_BIG_L0: &str = cix_var_qb2_dex::X25519_CIPHER_QB2_BIG_L0;
    /// X25519 sealed box cipher bytes of QB2 plaintext big lead size 1
    pub const X25519_CIPHER_QB2_BIG_L1: &str = cix_var_qb2_dex::X25519_CIPHER_QB2_BIG_L1;
    /// X25519 sealed box cipher bytes of QB2 plaintext big lead size 2
    pub const X25519_CIPHER_QB2_BIG_L2: &str = cix_var_qb2_dex::X25519_CIPHER_QB2_BIG_L2;

    pub static MAP: Lazy<HashMap<&'static str, &'static str>> = Lazy::new(|| {
        let mut map = HashMap::new();
        map.insert(X25519_CIPHER_L0, "X25519_CIPHER_L0");
        map.insert(X25519_CIPHER_L1, "X25519_CIPHER_L1");
        map.insert(X25519_CIPHER_L2, "X25519_CIPHER_L2");
        map.insert(X25519_CIPHER_BIG_L0, "X25519_CIPHER_BIG_L0");
        map.insert(X25519_CIPHER_BIG_L1, "X25519_CIPHER_BIG_L1");
        map.insert(X25519_CIPHER_BIG_L2, "X25519_CIPHER_BIG_L2");
        map.insert(X25519_CIPHER_QB64_L0, "X25519_CIPHER_QB64_L0");
        map.insert(X25519_CIPHER_QB64_L1, "X25519_CIPHER_QB64_L1");
        map.insert(X25519_CIPHER_QB64_L2, "X25519_CIPHER_QB64_L2");
        map.insert(X25519_CIPHER_QB64_BIG_L0, "X25519_CIPHER_QB64_BIG_L0");
        map.insert(X25519_CIPHER_QB64_BIG_L1, "X25519_CIPHER_QB64_BIG_L1");
        map.insert(X25519_CIPHER_QB64_BIG_L2, "X25519_CIPHER_QB64_BIG_L2");
        map.insert(X25519_CIPHER_QB2_L0, "X25519_CIPHER_QB2_L0");
        map.insert(X25519_CIPHER_QB2_L1, "X25519_CIPHER_QB2_L1");
        map.insert(X25519_CIPHER_QB2_L2, "X25519_CIPHER_QB2_L2");
        map.insert(X25519_CIPHER_QB2_BIG_L0, "X25519_CIPHER_QB2_BIG_L0");
        map.insert(X25519_CIPHER_QB2_BIG_L1, "X25519_CIPHER_QB2_BIG_L1");
        map.insert(X25519_CIPHER_QB2_BIG_L2, "X25519_CIPHER_QB2_BIG_L2");
        map
    });

    pub static TUPLE: [&'static str; 18] = [
        X25519_CIPHER_L0,
        X25519_CIPHER_L1,
        X25519_CIPHER_L2,
        X25519_CIPHER_BIG_L0,
        X25519_CIPHER_BIG_L1,
        X25519_CIPHER_BIG_L2,
        X25519_CIPHER_QB64_L0,
        X25519_CIPHER_QB64_L1,
        X25519_CIPHER_QB64_L2,
        X25519_CIPHER_QB64_BIG_L0,
        X25519_CIPHER_QB64_BIG_L1,
        X25519_CIPHER_QB64_BIG_L2,
        X25519_CIPHER_QB2_L0,
        X25519_CIPHER_QB2_L1,
        X25519_CIPHER_QB2_L2,
        X25519_CIPHER_QB2_BIG_L0,
        X25519_CIPHER_QB2_BIG_L1,
        X25519_CIPHER_QB2_BIG_L2,
    ];
}

/// Module for X25519 cipher codes for all sizes and all types of plaintext
#[allow(dead_code)]
pub mod cix_dex {
    use super::{cix_fix_qb64_dex, cix_var_dex};
    use once_cell::sync::Lazy;
    use std::collections::HashMap;

    // Variable size codes for stream plaintext
    /// X25519 sealed box cipher bytes of sniffable stream plaintext lead size 0
    pub const X25519_CIPHER_L0: &str = cix_var_dex::X25519_CIPHER_L0;
    /// X25519 sealed box cipher bytes of sniffable stream plaintext lead size 1
    pub const X25519_CIPHER_L1: &str = cix_var_dex::X25519_CIPHER_L1;
    /// X25519 sealed box cipher bytes of sniffable stream plaintext lead size 2
    pub const X25519_CIPHER_L2: &str = cix_var_dex::X25519_CIPHER_L2;
    /// X25519 sealed box cipher bytes of sniffable stream plaintext big lead size 0
    pub const X25519_CIPHER_BIG_L0: &str = cix_var_dex::X25519_CIPHER_BIG_L0;
    /// X25519 sealed box cipher bytes of sniffable stream plaintext big lead size 1
    pub const X25519_CIPHER_BIG_L1: &str = cix_var_dex::X25519_CIPHER_BIG_L1;
    /// X25519 sealed box cipher bytes of sniffable stream plaintext big lead size 2
    pub const X25519_CIPHER_BIG_L2: &str = cix_var_dex::X25519_CIPHER_BIG_L2;

    // Fixed size codes
    /// X25519 sealed box 124 char qb64 Cipher of 44 char qb64 Seed
    pub const X25519_CIPHER_SEED: &str = cix_fix_qb64_dex::X25519_CIPHER_SEED;
    /// X25519 sealed box 100 char qb64 Cipher of 24 char qb64 Salt
    pub const X25519_CIPHER_SALT: &str = cix_fix_qb64_dex::X25519_CIPHER_SALT;

    // Variable size codes for QB64 plaintext
    /// X25519 sealed box cipher bytes of QB64 plaintext lead size 0
    pub const X25519_CIPHER_QB64_L0: &str = cix_var_dex::X25519_CIPHER_QB64_L0;
    /// X25519 sealed box cipher bytes of QB64 plaintext lead size 1
    pub const X25519_CIPHER_QB64_L1: &str = cix_var_dex::X25519_CIPHER_QB64_L1;
    /// X25519 sealed box cipher bytes of QB64 plaintext lead size 2
    pub const X25519_CIPHER_QB64_L2: &str = cix_var_dex::X25519_CIPHER_QB64_L2;
    /// X25519 sealed box cipher bytes of QB64 plaintext big lead size 0
    pub const X25519_CIPHER_QB64_BIG_L0: &str = cix_var_dex::X25519_CIPHER_QB64_BIG_L0;
    /// X25519 sealed box cipher bytes of QB64 plaintext big lead size 1
    pub const X25519_CIPHER_QB64_BIG_L1: &str = cix_var_dex::X25519_CIPHER_QB64_BIG_L1;
    /// X25519 sealed box cipher bytes of QB64 plaintext big lead size 2
    pub const X25519_CIPHER_QB64_BIG_L2: &str = cix_var_dex::X25519_CIPHER_QB64_BIG_L2;

    // Variable size codes for QB2 plaintext
    /// X25519 sealed box cipher bytes of QB2 plaintext lead size 0
    pub const X25519_CIPHER_QB2_L0: &str = cix_var_dex::X25519_CIPHER_QB2_L0;
    /// X25519 sealed box cipher bytes of QB2 plaintext lead size 1
    pub const X25519_CIPHER_QB2_L1: &str = cix_var_dex::X25519_CIPHER_QB2_L1;
    /// X25519 sealed box cipher bytes of QB2 plaintext lead size 2
    pub const X25519_CIPHER_QB2_L2: &str = cix_var_dex::X25519_CIPHER_QB2_L2;
    /// X25519 sealed box cipher bytes of QB2 plaintext big lead size 0
    pub const X25519_CIPHER_QB2_BIG_L0: &str = cix_var_dex::X25519_CIPHER_QB2_BIG_L0;
    /// X25519 sealed box cipher bytes of QB2 plaintext big lead size 1
    pub const X25519_CIPHER_QB2_BIG_L1: &str = cix_var_dex::X25519_CIPHER_QB2_BIG_L1;
    /// X25519 sealed box cipher bytes of QB2 plaintext big lead size 2
    pub const X25519_CIPHER_QB2_BIG_L2: &str = cix_var_dex::X25519_CIPHER_QB2_BIG_L2;

    pub static MAP: Lazy<HashMap<&'static str, &'static str>> = Lazy::new(|| {
        let mut map = HashMap::new();

        map.insert(X25519_CIPHER_L0, "X25519_CIPHER_L0");
        map.insert(X25519_CIPHER_L1, "X25519_CIPHER_L1");
        map.insert(X25519_CIPHER_L2, "X25519_CIPHER_L2");
        map.insert(X25519_CIPHER_BIG_L0, "X25519_CIPHER_BIG_L0");
        map.insert(X25519_CIPHER_BIG_L1, "X25519_CIPHER_BIG_L1");
        map.insert(X25519_CIPHER_BIG_L2, "X25519_CIPHER_BIG_L2");
        map.insert(X25519_CIPHER_SEED, "X25519_CIPHER_SEED");
        map.insert(X25519_CIPHER_SALT, "X25519_CIPHER_SALT");
        map.insert(X25519_CIPHER_QB64_L0, "X25519_CIPHER_QB64_L0");
        map.insert(X25519_CIPHER_QB64_L1, "X25519_CIPHER_QB64_L1");
        map.insert(X25519_CIPHER_QB64_L2, "X25519_CIPHER_QB64_L2");
        map.insert(X25519_CIPHER_QB64_BIG_L0, "X25519_CIPHER_QB64_BIG_L0");
        map.insert(X25519_CIPHER_QB64_BIG_L1, "X25519_CIPHER_QB64_BIG_L1");
        map.insert(X25519_CIPHER_QB64_BIG_L2, "X25519_CIPHER_QB64_BIG_L2");
        map.insert(X25519_CIPHER_QB2_L0, "X25519_CIPHER_QB2_L0");
        map.insert(X25519_CIPHER_QB2_L1, "X25519_CIPHER_QB2_L1");
        map.insert(X25519_CIPHER_QB2_L2, "X25519_CIPHER_QB2_L2");
        map.insert(X25519_CIPHER_QB2_BIG_L0, "X25519_CIPHER_QB2_BIG_L0");
        map.insert(X25519_CIPHER_QB2_BIG_L1, "X25519_CIPHER_QB2_BIG_L1");
        map.insert(X25519_CIPHER_QB2_BIG_L2, "X25519_CIPHER_QB2_BIG_L2");
        map
    });

    pub static TUPLE: [&'static str; 20] = [
        X25519_CIPHER_L0,
        X25519_CIPHER_L1,
        X25519_CIPHER_L2,
        X25519_CIPHER_BIG_L0,
        X25519_CIPHER_BIG_L1,
        X25519_CIPHER_BIG_L2,
        X25519_CIPHER_SEED,
        X25519_CIPHER_SALT,
        X25519_CIPHER_QB64_L0,
        X25519_CIPHER_QB64_L1,
        X25519_CIPHER_QB64_L2,
        X25519_CIPHER_QB64_BIG_L0,
        X25519_CIPHER_QB64_BIG_L1,
        X25519_CIPHER_QB64_BIG_L2,
        X25519_CIPHER_QB2_L0,
        X25519_CIPHER_QB2_L1,
        X25519_CIPHER_QB2_L2,
        X25519_CIPHER_QB2_BIG_L0,
        X25519_CIPHER_QB2_BIG_L1,
        X25519_CIPHER_QB2_BIG_L2,
    ];
}

use crate::cesr::cigar::Cigar;
use crate::cesr::indexing::siger::Siger;
use crate::errors::MatterError;
use sodiumoxide::crypto::box_::curve25519xsalsa20poly1305 as crypto_box;
use sodiumoxide::crypto::sign::ed25519;

/// Convert an Ed25519 public key to an X25519 public key
pub fn ed25519_pk_to_x25519_pk(
    ed_pk: &ed25519::PublicKey,
) -> Result<crypto_box::PublicKey, MatterError> {
    // In libsodium, there's a crypto_sign_ed25519_pk_to_curve25519 function
    // We need to implement this conversion for sodiumoxide

    // The first step is to extract the raw bytes from the Ed25519 public key
    let ed_pk_bytes = ed_pk.as_ref();

    // We need access to the underlying curve25519 conversion
    // You'll need to use the libsodium-sys crate directly for this

    let mut curve_pk = [0u8; 32];

    // SAFETY: This is a FFI call to libsodium
    let result = unsafe {
        libsodium_sys::crypto_sign_ed25519_pk_to_curve25519(
            curve_pk.as_mut_ptr(),
            ed_pk_bytes.as_ptr(),
        )
    };

    if result != 0 {
        return Err(MatterError::CryptoError(
            "Failed to convert Ed25519 public key to X25519".to_string(),
        ));
    }

    // Convert the raw bytes to a sodiumoxide X25519 public key
    crypto_box::PublicKey::from_slice(&curve_pk).ok_or(MatterError::CryptoError(
        "Failed to convert Ed25519 public key to X25519".to_string(),
    ))
}

/// Convert an Ed25519 secret key to an X25519 secret key
pub fn ed25519_sk_to_x25519_sk(
    ed_sk: &ed25519::SecretKey,
) -> Result<crypto_box::SecretKey, MatterError> {
    // In libsodium, there's a crypto_sign_ed25519_sk_to_curve25519 function

    // Extract the raw bytes from the Ed25519 secret key
    let ed_sk_bytes = ed_sk.as_ref();

    let mut curve_sk = [0u8; 32];

    // SAFETY: This is a FFI call to libsodium
    let result = unsafe {
        libsodium_sys::crypto_sign_ed25519_sk_to_curve25519(
            curve_sk.as_mut_ptr(),
            ed_sk_bytes.as_ptr(),
        )
    };

    if result != 0 {
        return Err(MatterError::CryptoError(
            "Failed to convert Ed25519 secret key to X25519".to_string(),
        ));
    }

    // Convert the raw bytes to a sodiumoxide X25519 secret key
    crypto_box::SecretKey::from_slice(&curve_sk).ok_or(MatterError::CryptoError(
        "Failed to convert Ed25519 secret key to X25519".to_string(),
    ))
}
