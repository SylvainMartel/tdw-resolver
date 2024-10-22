//! Core types for DID:TDW resolution.
//!
//! This module provides the fundamental data structures needed for DID resolution,
//! including DID Documents, DID Log entries, and resolution-specific types.

use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc};

/// A complete DID Document as defined in the DID Core specification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DIDDocument {
    /// The context of the DID Document
    #[serde(rename = "@context")]
    pub context: Vec<String>,

    /// The DID itself
    pub id: String,

    /// Other DIDs that are associated with this DID Document
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "alsoKnownAs")]
    pub also_known_as: Option<Vec<String>>,

    /// Verification methods associated with this DID
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "verificationMethod")]
    pub verification_method: Option<Vec<VerificationMethod>>,

    /// Authentication verification methods
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authentication: Option<Vec<String>>,

    /// Assertion verification methods
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "assertionMethod")]
    pub assertion_method: Option<Vec<String>>,

    /// Services associated with this DID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service: Option<Vec<Service>>,

    /// Deactivation status
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deactivated: Option<bool>,
}

/// A verification method in a DID Document
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationMethod {
    /// The unique identifier for this verification method
    pub id: String,

    /// The type of the verification method
    #[serde(rename = "type")]
    pub method_type: String,

    /// The controller of this verification method
    pub controller: String,

    /// The public key in multibase format
    #[serde(rename = "publicKeyMultibase")]
    pub public_key_multibase: String,
}

/// A service endpoint in a DID Document
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Service {
    /// The unique identifier for this service
    pub id: String,

    /// The type of the service
    #[serde(rename = "type")]
    pub service_type: String,

    /// The endpoint URL or object
    #[serde(rename = "serviceEndpoint")]
    pub service_endpoint: serde_json::Value,
}

/// A DID Log entry for DID:TDW
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DIDLogEntry {
    /// Version ID combining version number and entry hash
    #[serde(rename = "versionId")]
    pub version_id: String,

    /// Entry timestamp
    #[serde(rename = "versionTime")]
    #[serde(with = "chrono::serde::ts_seconds")]
    pub version_time: DateTime<Utc>,

    /// DID configuration parameters
    pub parameters: DIDParameters,

    /// The DID Document state for this version
    pub state: DIDDocument,

    /// Proofs for this entry
    pub proof: Vec<Proof>,

    /// The predecessor's version_id (SCID for first entry, complete version_id for others)
    #[serde(skip)]  // Don't serialize this field, it's just for verification
    pub last_version_id: String,
}

/// Parameters for DID configuration and verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DIDParameters {
    /// The DID method version
    pub method: String,

    /// The SCID for the DID
    pub scid: Option<String>,

    /// Update keys (only needed for verification)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub update_keys: Option<Vec<String>>,

    /// Indicates if the DID is deactivated
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deactivated: Option<bool>,

    /// Cache time-to-live in seconds
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl: Option<u64>,
}

/// Data Integrity Proof
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proof {
    /// The type of proof
    #[serde(rename = "type")]
    pub proof_type: String,

    /// When the proof was created
    #[serde(with = "chrono::serde::ts_seconds")]
    pub created: DateTime<Utc>,

    /// The verification method used
    #[serde(rename = "verificationMethod")]
    pub verification_method: String,

    /// The purpose of the proof
    #[serde(rename = "proofPurpose")]
    pub proof_purpose: ProofPurpose,

    /// The actual proof value
    #[serde(rename = "proofValue")]
    pub proof_value: String,

    /// Optional challenge used in the proof
    pub challenge: Option<String>,
}

/// Purpose of a proof
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProofPurpose {
    #[serde(rename = "authentication")]
    Authentication,
    #[serde(rename = "assertionMethod")]
    AssertionMethod,
}

/// A complete DID Log containing all entries
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DIDLog {
    pub entries: Vec<DIDLogEntry>,
}

/// Resolution result containing the DID Document and metadata
#[derive(Debug, Clone)]
pub struct ResolutionResult {
    /// The resolved DID Document
    pub did_document: DIDDocument,

    /// Metadata about the resolution process
    pub metadata: ResolutionMetadata,
}

/// Metadata about the resolution process
#[derive(Debug, Clone)]
pub struct ResolutionMetadata {
    /// Content type of the resolved document
    pub content_type: String,

    /// When the document was retrieved
    pub retrieved: DateTime<Utc>,

    /// How long the resolution took
    pub duration: std::time::Duration,

    /// Number of versions in the DID log
    pub versions_count: usize,

    /// Any error that occurred during resolution
    pub error: Option<String>,
}

/// Options for DID resolution
#[derive(Debug, Clone)]
pub struct ResolutionOptions {
    /// Specific version ID to resolve
    pub version_id: Option<String>,

    /// Point in time to resolve the DID
    pub version_time: Option<DateTime<Utc>>,
}