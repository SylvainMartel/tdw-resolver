//! Proof verification functionality.
//!
//! This module handles the verification of proofs in DID Log entries during
//! resolution. For resolution purposes, this only verifies the presence and
//! format of proofs, not their cryptographic validity.

use crate::error::ResolutionError;
use crate::types::{DIDLogEntry, DIDParameters};

/// Verifies the proof(s) in a DID Log entry
///
/// For resolution purposes, this only verifies that proofs exist and are properly
/// formatted. Cryptographic verification of proofs is not required for basic
/// resolution.
pub fn verify_proof(entry: &DIDLogEntry, parameters: &DIDParameters) -> Result<(), ResolutionError> {
    // Verify that proofs exist
    if entry.proof.is_empty() {
        return Err(ResolutionError::InvalidProof);
    }

    // Verify that at least one proof exists and has required fields
    let proof = entry.proof.first().ok_or(ResolutionError::InvalidProof)?;

    // Verify proof contains required fields
    if proof.verification_method.is_empty() || proof.proof_value.is_empty() {
        return Err(ResolutionError::InvalidProof);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use crate::types::{Proof, ProofPurpose};

    fn create_test_proof() -> Proof {
        Proof {
            proof_type: "DataIntegrityProof".to_string(),
            created: Utc::now(),
            verification_method: "test-method".to_string(),
            proof_purpose: ProofPurpose::Authentication,
            proof_value: "test-value".to_string(),
            challenge: None,
        }
    }

    fn create_test_entry() -> DIDLogEntry {
        DIDLogEntry {
            version_id: "1-test".to_string(),
            version_time: Utc::now(),
            parameters: DIDParameters {
                method: "did:tdw:0.4".to_string(),
                scid: None,
                update_keys: Some(vec!["test-key".to_string()]),
                portable: Some(false),
                prerotation: Some(false),
                next_key_hashes: Some(vec!["test-hash".to_string()]),
                deactivated: None,
                ttl: None,
            },
            state: crate::types::DIDDocument {
                context: vec!["https://www.w3.org/ns/did/v1".to_string()],
                id: "did:tdw:test:example.com".to_string(),
                also_known_as: None,
                verification_method: None,
                authentication: None,
                assertion_method: None,
                service: None,
                deactivated: None,
            },
            proof: vec![create_test_proof()],
            last_version_id: "test-scid".to_string(),
        }
    }

    fn create_test_parameters() -> DIDParameters {
        DIDParameters {
            method: "did:tdw:0.4".to_string(),
            scid: None,
            update_keys: Some(vec!["test-key".to_string()]),
            portable: Some(false),
            prerotation: Some(false),
            next_key_hashes: Some(vec!["test-hash".to_string()]),
            deactivated: None,
            ttl: None,
        }
    }

    #[test]
    fn test_valid_proof() {
        let entry = create_test_entry();
        let parameters = create_test_parameters();
        assert!(verify_proof(&entry, &parameters).is_ok());
    }

    #[test]
    fn test_missing_proof() {
        let mut entry = create_test_entry();
        entry.proof = vec![];
        let parameters = create_test_parameters();
        assert!(matches!(
            verify_proof(&entry, &parameters),
            Err(ResolutionError::InvalidProof)
        ));
    }

    #[test]
    fn test_invalid_proof_fields() {
        let mut entry = create_test_entry();
        entry.proof[0].verification_method = "".to_string();
        let parameters = create_test_parameters();
        assert!(matches!(
            verify_proof(&entry, &parameters),
            Err(ResolutionError::InvalidProof)
        ));
    }
}