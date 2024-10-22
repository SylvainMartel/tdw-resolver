//! Entry hash verification functionality.
//!
//! This module handles the verification of DID Log entry hashes, ensuring the
//! integrity of the DID Log chain.

use crate::error::ResolutionError;
use crate::types::DIDLogEntry;
use sha2::{Sha256, Digest};
use base58::ToBase58;
use multihash::Multihash;
use serde_json_canonicalizer::to_string as jcs_canonicalize;

use super::SHA2_256;

/// Verifies the hash in a DID Log entry's versionId
pub fn verify_entry_hash(entry: &DIDLogEntry) -> Result<(), ResolutionError> {
    let parts: Vec<&str> = entry.version_id.split('-').collect();
    if parts.len() != 2 {
        return Err(ResolutionError::InvalidVersionId);
    }

    let version_number = parts[0].parse::<u64>()
        .map_err(|_| ResolutionError::InvalidVersionId)?;

    // Create verification entry, using appropriate predecessor version_id
    let mut verify_entry = entry.clone();
    if version_number == 1 {
        // For first entry, use SCID
        verify_entry.version_id = verify_entry.parameters.scid
            .clone()
            .ok_or(ResolutionError::InvalidVersionId)?;
    } else {
        verify_entry.version_id = verify_entry.last_version_id.clone();
    }
    let calculated_hash = calculate_entry_hash(&verify_entry)?;

    // Verify hash matches
    if parts[1] != calculated_hash {
        return Err(ResolutionError::InvalidEntryHash);
    }

    println!("Verification details:");
    println!("  Original entry version_id: {}", entry.version_id);
    println!("  Version used for hash calc: {}", verify_entry.version_id);
    println!("  Calculated hash: {}", calculated_hash);
    println!("  Expected hash: {}", parts[1]);

    Ok(())
}

/// Calculates the hash for a DID Log entry
fn calculate_entry_hash(entry: &DIDLogEntry) -> Result<String, ResolutionError> {
    println!("\nCALCULATE_ENTRY_HASH:");
    println!("Input entry version_id: {}", entry.version_id);
    // Create entry copy without proof for hashing
    let entry_for_hash = DIDLogEntry {
        version_id: entry.version_id.clone(),
        version_time: entry.version_time,
        parameters: entry.parameters.clone(),
        state: entry.state.clone(),
        proof: vec![], // Exclude proof as per spec
        last_version_id: entry.last_version_id.clone(),
    };

    // Canonicalize the entry
    let canonical_json = jcs_canonicalize(&entry_for_hash)
        .map_err(|e| ResolutionError::CanonicalizeError(e.to_string()))?;

    println!("Canonical JSON for hash calculation:");
    println!("{}", canonical_json);

    // Calculate hash
    let hash = Sha256::digest(canonical_json.as_bytes());

    // Create multihash
    let multihash = Multihash::<64>::wrap(SHA2_256, &hash)
        .map_err(|e| ResolutionError::MultihashError(e.to_string()))?;
    let final_hash = multihash.to_bytes().to_base58();

    println!("Calculated hash: {}", final_hash);

    Ok(final_hash)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use crate::types::{DIDDocument, DIDParameters};
    use crate::resolver::Resolver;

    fn create_test_entry(predecessor_version_id: Option<String>) -> DIDLogEntry {
        let scid = "QmfGEUAcMpzo25kF2Rhn8L5FAXysfGnkzjwdKoNPi615XQ";


        let version_id = predecessor_version_id.clone().unwrap_or_else(|| scid.to_string());
        DIDLogEntry {
            // Use provided predecessor_version_id or SCID
            version_id: version_id.clone(),
            version_time: Utc::now(),
            parameters: DIDParameters {
                method: "did:tdw:0.4".to_string(),
                scid: Some(scid.to_string()),
                update_keys: None,
                deactivated: None,
                ttl: None,
            },
            state: DIDDocument {
                context: vec!["https://www.w3.org/ns/did/v1".to_string()],
                id: format!("did:tdw:{}:example.com", scid),
                also_known_as: None,
                verification_method: None,
                authentication: None,
                assertion_method: None,
                service: None,
                deactivated: None,
            },
            proof: vec![],
            // Initialize last_version_id with predecessor_version_id or SCID
            last_version_id: version_id,

        }
    }

    #[test]
    fn test_first_entry_hash() {
        // Create first entry with SCID as versionId
        let mut entry = create_test_entry(None);
        println!("entry is {:?}", entry);


        // Set last_version_id to SCID for first entry
        entry.last_version_id = entry.parameters.scid.clone().unwrap();

        // Calculate hash
        let hash = calculate_entry_hash(&entry).unwrap();
        println!("hash is {}", hash);

        // Set final versionId
        entry.version_id = format!("1-{}", hash);

        assert!(verify_entry_hash(&entry).is_ok());
    }

    #[test]
    fn test_subsequent_version_hash() {
        // Create first entry
        let mut entry1 = create_test_entry(None);
        let scid = entry1.parameters.scid.clone().unwrap();
        entry1.last_version_id = scid.clone();
        let hash1 = calculate_entry_hash(&entry1).unwrap();
        entry1.version_id = format!("1-{}", hash1);
        assert!(verify_entry_hash(&entry1).is_ok());

        // Create second entry
        let mut entry2 = entry1.clone();
        entry2.last_version_id = entry1.version_id.clone();  // Use entry1's complete version_id
        let hash2 = calculate_entry_hash(&entry2).unwrap();
        entry2.version_id = format!("2-{}", hash2);

        println!("Entry 1 versionId: {}", entry1.version_id);
        println!("Entry 2 versionId: {}", entry2.version_id);

        assert!(verify_entry_hash(&entry2).is_ok());
    }
}