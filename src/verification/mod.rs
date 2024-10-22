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

// Constants shared across verification modules
const SHA2_256: u64 = 0x12;
const SCID_PLACEHOLDER: &str = "{SCID}";