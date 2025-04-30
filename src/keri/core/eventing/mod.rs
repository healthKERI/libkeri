mod incept;
mod interact;
mod query;
mod receipt;
mod reply;
mod rotate;

use crate::Matter;
use std::error::Error;

pub use incept::*;

// Determine threshold representations based on intive flag
const MAX_INT_THOLD: usize = 12; // Define this constant based on your system

fn ample(n: usize) -> usize {
    // Implementation for ample - computes witness threshold
    std::cmp::max(1, (n as f64 / 2.0).ceil() as usize)
}

fn is_digest_code(code: &str) -> bool {
    // Check if code is in DigDex
    ["E", "S", "X"].contains(&code)
}

fn is_prefix_code(code: &str) -> bool {
    // Check if code is in PreDex
    ["A", "B", "C", "D"].contains(&code)
}
