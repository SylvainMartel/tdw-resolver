//! Error types for DID:TDW resolution operations.
//!
//! This module provides a comprehensive set of error types that can occur during
//! DID resolution operations. It uses the `thiserror` crate for error handling.

use thiserror::Error;
use url::ParseError;

/// Errors that can occur during DID:TDW resolution operations
#[derive(Error, Debug)]
pub enum ResolutionError {
    /// The DID format is invalid
    #[error("Invalid DID format")]
    InvalidDIDFormat,

    /// The DID resolution operation failed
    #[error("DID resolution failed: {0}")]
    ResolutionFailed(String),

    /// The DID Log entry is invalid
    #[error("Invalid DID Log entry")]
    InvalidLogEntry,

    /// The proof in the DID Log entry is invalid
    #[error("Invalid proof in DID Log entry")]
    InvalidProof,

    /// The version ID format is invalid
    #[error("Invalid version ID format")]
    InvalidVersionId,

    /// The version number is invalid
    #[error("Invalid version number")]
    InvalidVersionNumber,

    /// The entry hash is invalid
    #[error("Invalid entry hash")]
    InvalidEntryHash,

    /// The version time is invalid
    #[error("Invalid version time")]
    InvalidVersionTime,

    /// The version time is in the future
    #[error("Future version time")]
    FutureVersionTime,

    /// The SCID is invalid
    #[error("Invalid SCID")]
    InvalidSCID,

    /// The requested version was not found
    #[error("Version not found")]
    VersionNotFound,

    /// No document was found
    #[error("No document found")]
    NoDocumentFound,

    /// HTTP request error
    #[error("HTTP request error: {0}")]
    RequestError(#[from] reqwest::Error),

    /// URL parse error
    #[error("URL parse error: {0}")]
    UrlError(#[from] ParseError),

    /// JSON error
    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),

    /// Base58 decoding error
    #[error("Base58 decoding error: {0}")]
    Base58DecodeError(String),

    /// JSON canonicalization error
    #[error("Canonicalization error: {0}")]
    CanonicalizeError(String),

    /// Invalid DID Log
    #[error("Invalid DID Log: {0}")]
    InvalidDIDLog(String),

    /// Multihash error
    #[error("Multihash error: {0}")]
    MultihashError(String),
}