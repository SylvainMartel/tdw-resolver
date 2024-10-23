//! SCID verification functionality.
//!
//! This module handles the verification of Self-Certifying Identifiers (SCIDs)
//! during DID resolution.

use crate::error::ResolutionError;
use crate::types::DIDLogEntry;
use sha2::{Sha256, Digest};
use base58::ToBase58;
use multihash::Multihash;
use serde_json_canonicalizer::to_string as jcs_canonicalize;

use super::{SHA2_256, SCID_PLACEHOLDER};

/// Verifies a SCID against a DID Log entry
pub fn verify_scid(scid: &str, entry: &DIDLogEntry) -> Result<(), ResolutionError> {
    let calculated_scid = generate_scid(entry)?;

    if scid != calculated_scid {
        return Err(ResolutionError::InvalidSCID);
    }

    Ok(())
}

/// Generates a SCID from a DID Log entry
fn generate_scid(entry: &DIDLogEntry) -> Result<String, ResolutionError> {
    // Create entry copy with SCID placeholder
    let mut entry_copy = entry.clone();
    entry_copy.version_id = SCID_PLACEHOLDER.to_string();
    if let Some(ref mut params) = entry_copy.parameters.scid {
        *params = SCID_PLACEHOLDER.to_string();
    }

    // Canonicalize the entry
    let canonical_json = jcs_canonicalize(&entry_copy)
        .map_err(|e| ResolutionError::CanonicalizeError(e.to_string()))?;

    // Calculate hash
    let hash = Sha256::digest(canonical_json.as_bytes());

    // Create multihash
    let multihash = Multihash::<64>::wrap(SHA2_256, &hash)
        .map_err(|e| ResolutionError::MultihashError(e.to_string()))?;

    Ok(multihash.to_bytes().to_base58())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use crate::types::{DIDDocument, DIDParameters};

    fn create_test_entry() -> DIDLogEntry {
        DIDLogEntry {
            version_id: SCID_PLACEHOLDER.to_string(),
            version_time: Utc::now(),
            parameters: DIDParameters {
                method: "did:tdw:0.4".to_string(),
                scid: Some(SCID_PLACEHOLDER.to_string()),
                update_keys: Some(vec!["test-key".to_string()]),
                portable: Some(false),
                prerotation: Some(false),
                next_key_hashes: Some(vec!["test-hash".to_string()]),
                deactivated: None,
                ttl: None,
            },
            state: DIDDocument {
                context: vec!["https://www.w3.org/ns/did/v1".to_string()],
                id: format!("did:tdw:{}:example.com", SCID_PLACEHOLDER),
                also_known_as: None,
                verification_method: None,
                authentication: None,
                assertion_method: None,
                service: None,
                deactivated: None,
            },
            proof: vec![],
            last_version_id: "test-scid".to_string(),
        }
    }

    #[test]
    fn test_scid_generation() {
        let entry = create_test_entry();
        let scid = generate_scid(&entry).unwrap();
        assert!(!scid.is_empty());
    }

    #[test]
    fn test_scid_verification() {
        let entry = create_test_entry();
        let scid = generate_scid(&entry).unwrap();
        assert!(verify_scid(&scid, &entry).is_ok());
    }

    #[test]
    fn test_invalid_scid() {
        let entry = create_test_entry();
        assert!(matches!(
            verify_scid("invalid-scid", &entry),
            Err(ResolutionError::InvalidSCID)
        ));
    }
}