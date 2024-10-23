//! Verification functionality for DID:TDW resolution.
//!
//! This module provides the verification functions needed during DID resolution,
//! including entry hash verification, SCID verification, and proof verification.

mod entry;
mod proof;
mod scid;

pub use entry::verify_entry_hash;
pub use proof::verify_proof;
pub use scid::verify_scid;


use crate::error::ResolutionError;
use sha2::{Sha256, Digest};
use base58::ToBase58;
use multihash::Multihash;

// Constants shared across verification modules
const SHA2_256: u64 = 0x12;
const SCID_PLACEHOLDER: &str = "{SCID}";

/// Generates a hash of a key for pre-rotation verification
pub fn generate_key_hash(key: &str) -> Result<String, ResolutionError> {
    let hash = Sha256::digest(key.as_bytes());
    let multihash = Multihash::<64>::wrap(SHA2_256, &hash)
        .map_err(|e| ResolutionError::MultihashError(e.to_string()))?;
    Ok(multihash.to_bytes().to_base58())
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_key_hash() {
        let key = "z6MkhbNRN2Q9BaY9TvTc2K3izkhfVwgHiXL7VWZnTqxEvc3R";
        let hash = generate_key_hash(key).unwrap();

        // Hash should be deterministic
        assert_eq!(hash, generate_key_hash(key).unwrap());

        // Should produce a valid base58 string
        assert!(hash.chars().all(|c| "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".contains(c)));
    }

    #[test]
    fn test_different_keys_different_hashes() {
        let key1 = "z6MkhbNRN2Q9BaY9TvTc2K3izkhfVwgHiXL7VWZnTqxEvc3R";
        let key2 = "z6MkvQnUuQn3s52dw4FF3T87sfaTvXRW7owE1QMvFwpag2Bf";

        let hash1 = generate_key_hash(key1).unwrap();
        let hash2 = generate_key_hash(key2).unwrap();

        assert_ne!(hash1, hash2);
    }
}