//! Core DID resolution functionality.
//!
//! This module provides the main resolution logic for DID:TDW identifiers,
//! handling the fetching and verification of DID Logs, and the resolution
//! of DID Documents according to the DID:TDW specification.

use std::collections::HashSet;
use std::time::Instant;
use chrono::{DateTime, Utc};
use reqwest::Client;

use crate::error::ResolutionError;
use crate::types::{
    DIDDocument, DIDLogEntry, DIDLog, DIDParameters,
    ResolutionResult, ResolutionMetadata, ResolutionOptions
};
use crate::did::TdwDid;
use crate::verification::{verify_entry_hash, verify_scid, verify_proof, generate_key_hash};

/// Core resolver for DID:TDW resolution
pub struct Resolver {
    /// HTTP client for fetching DID Logs
    client: Client,
    /// Currently active DID parameters
    active_parameters: DIDParameters,
    /// Processed DID Documents with their version IDs and times
    processed_documents: Vec<(String, DateTime<Utc>, DIDDocument)>,
    /// Current version number being processed
    current_version: u64,
    pre_rotation_active: bool,
    next_key_hashes: HashSet<String>,

}

impl Resolver {
    /// Creates a new Resolver instance
    pub fn new() -> Self {
        Self {
            client: Client::new(),
            active_parameters: DIDParameters {
                method: "did:tdw:0.4".to_string(),
                scid: None,
                prerotation: None,
                next_key_hashes: None,
                portable: None,
                update_keys: None,
                deactivated: None,
                ttl: None,
            },
            processed_documents: Vec::new(),
            current_version: 0,
            pre_rotation_active: false,
            next_key_hashes: HashSet::new(),
        }
    }

    /// Resolves a DID:TDW identifier
    ///
    /// # Arguments
    /// * `did` - The DID to resolve
    /// * `options` - Optional resolution parameters
    ///
    /// # Example
    /// ```no_run
    /// use trustdidweb_resolver::{Resolver, ResolutionOptions};
    ///
    /// #[tokio::main]
    /// async fn main() -> Result<(), Box<dyn std::error::Error>> {
    ///     let mut resolver = Resolver::new();
    ///     let result = resolver.resolve(
    ///         "did:tdw:abc123:example.com",
    ///         None
    ///     ).await?;
    ///     println!("Resolved DID Document: {:?}", result.did_document);
    ///     Ok(())
    /// }
    /// ```
    pub async fn resolve(
        &mut self,
        did: &str,
        options: Option<ResolutionOptions>,
    ) -> Result<ResolutionResult, ResolutionError> {
        let start_time = Instant::now();

        // Parse the DID
        let tdw_did = TdwDid::parse(did)?;

        // Get the DID Log URL
        let url = tdw_did.to_url()?;

        // Fetch and process the DID Log
        let did_log = self.fetch_did_log(&url).await?;

        // Process all entries
        for entry in did_log.entries {
            self.process_log_entry(&entry)?;
        }

        // Get the requested version based on options
        let document = match &options {
            Some(opts) => {
                if let Some(version_id) = &opts.version_id {
                    self.get_document_by_version(version_id)?
                } else if let Some(version_time) = opts.version_time {
                    self.get_document_by_time(version_time)?
                } else {
                    self.get_latest_document()?
                }
            }
            None => self.get_latest_document()?,
        };

        // Create resolution metadata
        let metadata = ResolutionMetadata {
            content_type: "application/did+json".to_string(),
            retrieved: Utc::now(),
            duration: start_time.elapsed(),
            versions_count: self.processed_documents.len(),
            error: None,
        };

        Ok(ResolutionResult {
            did_document: document,
            metadata,
        })
    }

    async fn fetch_did_log(&self, url: &url::Url) -> Result<DIDLog, ResolutionError> {
        let response = self.client
            .get(url.clone())
            .send()
            .await
            .map_err(ResolutionError::from)?;

        println!("Status: {:?}", response);
        if !response.status().is_success() {
            return Err(ResolutionError::ResolutionFailed(
                format!("HTTP {} when fetching DID Log", response.status())
            ));
        }
    println!("Response Status: {:?}", response.status());
        let log_content = response.text().await?;
println!("Response Content: {:?}", log_content);
        // Parse each line as a DID Log Entry
        let entries = log_content
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| serde_json::from_str(line))
            .collect::<Result<Vec<DIDLogEntry>, _>>()
            .map_err(|e| ResolutionError::InvalidDIDLog(e.to_string()))?;

        Ok(DIDLog { entries })
    }

    fn process_log_entry(&mut self, entry: &DIDLogEntry) -> Result<(), ResolutionError> {
        // Update parameters
        self.update_parameters(&entry.parameters)?;

        // Verify version ID format and sequence
        self.verify_version_sequence(entry)?;

        // Verify entry hash
        verify_entry_hash(entry)?;

        // Verify version time
        self.verify_version_time(entry)?;

        // For first entry, verify SCID
        if self.current_version == 0 {
            verify_scid(
                self.active_parameters.scid.as_ref().ok_or(ResolutionError::InvalidSCID)?,
                entry
            )?;
        }

        // Verify pre-rotation if active
        if self.pre_rotation_active {
            self.verify_pre_rotation(entry)?;
        }

        // Verify entry proof
        verify_proof(entry, &self.active_parameters)?;

        // Store the processed document
        self.processed_documents.push((
            entry.version_id.clone(),
            entry.version_time,
            entry.state.clone()
        ));

        self.current_version += 1;

        Ok(())
    }

    fn verify_pre_rotation(&self, entry: &DIDLogEntry) -> Result<(), ResolutionError> {
        if let Some(update_keys) = &entry.parameters.update_keys {
            // Skip verification for first entry
            if self.current_version > 0 {
                // Verify all update keys have corresponding hashes
                for key in update_keys {
                    let key_hash = generate_key_hash(key)?;
                    if !self.next_key_hashes.contains(&key_hash) {
                        return Err(ResolutionError::KeyNotPreRotated);
                    }
                }
            }

            // Verify new next_key_hashes is provided
            if entry.parameters.next_key_hashes.is_none() {
                return Err(ResolutionError::MissingNextKeyHashes);
            }
        }
        Ok(())
    }
    fn update_parameters(&mut self, new_params: &DIDParameters) -> Result<(), ResolutionError> {
        // Always update method version
        self.active_parameters.method = new_params.method.clone();

        // Update SCID if provided
        if let Some(scid) = &new_params.scid {
            self.active_parameters.scid = Some(scid.clone());
        }

        // Update update_keys if provided
        if let Some(keys) = &new_params.update_keys {
            self.active_parameters.update_keys = Some(keys.clone());
        }

        // Handle pre-rotation parameters
        if let Some(prerotation) = new_params.prerotation {
            // Can't disable pre-rotation once enabled
            if self.pre_rotation_active && !prerotation {
                return Err(ResolutionError::CannotDeactivatePreRotation);
            }
            self.active_parameters.prerotation = Some(prerotation);
            self.pre_rotation_active = prerotation;
        }

        if let Some(next_key_hashes) = &new_params.next_key_hashes {
            self.active_parameters.next_key_hashes = Some(next_key_hashes.clone());
            self.next_key_hashes = next_key_hashes.iter().cloned().collect();
        }

        // Handle portable parameter
        if let Some(portable) = new_params.portable {
            // Can only set portable in first entry
            if self.current_version > 0 && self.active_parameters.portable.is_none() {
                return Err(ResolutionError::CannotEnablePortabilityAfterCreation);
            }
            self.active_parameters.portable = Some(portable);
        }


        // Update deactivated status if provided
        if let Some(deactivated) = new_params.deactivated {
            self.active_parameters.deactivated = Some(deactivated);
        }

        // Update TTL if provided
        if let Some(ttl) = new_params.ttl {
            self.active_parameters.ttl = Some(ttl);
        }

        Ok(())
    }

    fn verify_version_sequence(&self, entry: &DIDLogEntry) -> Result<(), ResolutionError> {
        let parts: Vec<&str> = entry.version_id.split('-').collect();
        if parts.len() != 2 {
            return Err(ResolutionError::InvalidVersionId);
        }

        let version_number = parts[0].parse::<u64>()
            .map_err(|_| ResolutionError::InvalidVersionId)?;

        if version_number != self.current_version + 1 {
            return Err(ResolutionError::InvalidVersionNumber);
        }

        Ok(())
    }

    fn verify_version_time(&self, entry: &DIDLogEntry) -> Result<(), ResolutionError> {
        if let Some(last_entry) = self.processed_documents.last() {
            if entry.version_time <= last_entry.1 {
                return Err(ResolutionError::InvalidVersionTime);
            }
        }

        if entry.version_time > Utc::now() {
            return Err(ResolutionError::FutureVersionTime);
        }

        Ok(())
    }

    fn get_document_by_version(&self, version_id: &str) -> Result<DIDDocument, ResolutionError> {
        self.processed_documents
            .iter()
            .find(|(id, _, _)| id == version_id)
            .map(|(_, _, doc)| doc.clone())
            .ok_or(ResolutionError::VersionNotFound)
    }

    fn get_document_by_time(&self, time: DateTime<Utc>) -> Result<DIDDocument, ResolutionError> {
        self.processed_documents
            .iter()
            .rev()
            .find(|(_, entry_time, _)| entry_time <= &time)
            .map(|(_, _, doc)| doc.clone())
            .ok_or(ResolutionError::VersionNotFound)
    }

    fn get_latest_document(&self) -> Result<DIDDocument, ResolutionError> {
        self.processed_documents
            .last()
            .map(|(_, _, doc)| doc.clone())
            .ok_or(ResolutionError::NoDocumentFound)
    }
}

/// Convenience function for resolving a DID without creating a Resolver instance
pub async fn resolve_did(
    did: &str,
    options: Option<ResolutionOptions>,
) -> Result<ResolutionResult, ResolutionError> {
    let mut resolver = Resolver::new();
    resolver.resolve(did, options).await
}

#[cfg(test)]
mod tests {
    use super::*;

    // TODO: Add tests that mock HTTP responses for DID Log fetching
    // TODO: Add tests for version resolution
    // TODO: Add tests for time-based resolution
    // TODO: Add tests for error cases

    #[tokio::test]
    async fn test_basic_resolution() {
        // This test will need to mock HTTP responses
        // Implementation pending
    }
}