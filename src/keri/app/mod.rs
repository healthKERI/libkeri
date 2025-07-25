mod configing;
pub mod habbing;
pub mod keeping;

/// Returns a bytes DB key from concatenation with '.' of qualified Base64 prefix
/// bytes `pre` and int `ri` (rotation index) of key rotation.
/// Inception has ri == 0
pub fn ri_key(pre: &[u8], ri: usize) -> Vec<u8> {
    let mut key = Vec::with_capacity(pre.len() + 1 + 32);
    key.extend_from_slice(pre);
    key.push(b'.'); // Add dot separator

    // Format ri as a 32-character zero-padded lowercase hex string
    let ri_hex = format!("{:032x}", ri);
    key.extend_from_slice(ri_hex.as_bytes());

    key
}
