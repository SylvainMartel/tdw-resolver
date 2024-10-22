//! DID parsing and URL transformation functionality.
//!
//! This module handles the parsing and validation of DID:TDW identifiers and their
//! transformation into HTTPS URLs for resolution.

use crate::error::ResolutionError;
use url::Url;

/// Represents a parsed DID:TDW identifier
#[derive(Debug, Clone, PartialEq)]
pub struct TdwDid {
    /// The Self-Certifying Identifier (SCID) component
    pub scid: String,
    /// The domain component
    pub domain: String,
    /// Optional port number
    pub port: Option<u16>,
    /// Optional path component
    pub path: Option<String>,
}

impl TdwDid {
    /// Creates a new TdwDid instance
    pub fn new(scid: String, domain: String, port: Option<u16>, path: Option<String>) -> Self {
        Self { scid, domain, port, path }
    }

    /// Converts the TdwDid to its string representation
    pub fn to_string(&self) -> String {
        let mut did = format!("did:tdw:{}:{}", self.scid, self.domain);
        if let Some(port) = self.port {
            did.push_str(&format!(":{}", port));
        }
        if let Some(path) = &self.path {
            did.push_str(&format!("/{}", path));
        }
        did
    }

    /// Converts the TdwDid to its corresponding HTTPS URL for DID resolution
    pub fn to_url(&self) -> Result<Url, ResolutionError> {
        let mut url = format!("https://{}", self.domain);
        if let Some(port) = self.port {
            url.push_str(&format!(":{}", port));
        }
        if let Some(path) = &self.path {
            url.push_str(&format!("/{}", path));
        } else {
            url.push_str("/.well-known");
        }
        url.push_str("/did.jsonl");

        Url::parse(&url).map_err(ResolutionError::from)
    }

    /// Converts the TdwDid to a URL for resolving specific paths
    pub fn to_path_url(&self, path: &str) -> Result<Url, ResolutionError> {
        let mut url = format!("https://{}", self.domain);
        if let Some(port) = self.port {
            url.push_str(&format!(":{}", port));
        }
        if let Some(base_path) = &self.path {
            url.push_str(&format!("/{}", base_path));
        }
        url.push_str(&format!("/{}", path));

        Url::parse(&url).map_err(ResolutionError::from)
    }

    /// Parses and validates a DID:TDW string
    pub fn parse(did: &str) -> Result<Self, ResolutionError> {
        let parts: Vec<&str> = did.split(':').collect();
        if parts.len() < 4 || parts[0] != "did" || parts[1] != "tdw" {
            return Err(ResolutionError::InvalidDIDFormat);
        }

        let scid = parts[2].to_string();
        let domain_and_rest = parts[3..].join(":");

        // Split domain/port from path
        let mut domain_parts = domain_and_rest.splitn(2, '/');
        let domain_and_port = domain_parts.next().unwrap();
        let path = domain_parts.next().map(|s| s.to_string());

        // Handle port if present
        let (domain, port) = if domain_and_port.contains(':') {
            let dp: Vec<&str> = domain_and_port.split(':').collect();
            (
                dp[0].to_string(),
                Some(dp[1].parse().map_err(|_| ResolutionError::InvalidDIDFormat)?)
            )
        } else {
            (domain_and_port.to_string(), None)
        };

        Ok(Self::new(scid, domain, port, path))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tdw_did_parsing() {
        let test_cases = vec![
            (
                "did:tdw:abc123:example.com:8080/path/to/resource",
                ("abc123", "example.com", Some(8080), Some("path/to/resource"))
            ),
            (
                "did:tdw:abc123:example.com/path/to/resource",
                ("abc123", "example.com", None, Some("path/to/resource"))
            ),
            (
                "did:tdw:abc123:example.com",
                ("abc123", "example.com", None, None)
            ),
            (
                "did:tdw:abc123:example.com:8080",
                ("abc123", "example.com", Some(8080), None)
            ),
        ];

        for (input, expected) in test_cases {
            let parsed = TdwDid::parse(input).unwrap();
            assert_eq!(parsed.scid, expected.0);
            assert_eq!(parsed.domain, expected.1);
            assert_eq!(parsed.port, expected.2);
            assert_eq!(parsed.path, expected.3.map(String::from));
        }
    }

    #[test]
    fn test_invalid_did_format() {
        let invalid_dids = vec![
            "did:web:example.com",
            "did:tdw:example.com",
            "did:tdw:abc123",
            "tdw:abc123:example.com",
        ];

        for did in invalid_dids {
            assert!(matches!(TdwDid::parse(did), Err(ResolutionError::InvalidDIDFormat)));
        }
    }

    #[test]
    fn test_url_transformation() {
        let test_cases = vec![
            (
                TdwDid::new(
                    "abc123".to_string(),
                    "example.com".to_string(),
                    Some(8080),
                    Some("path/to/resource".to_string())
                ),
                "https://example.com:8080/path/to/resource/did.jsonl"
            ),
            (
                TdwDid::new(
                    "abc123".to_string(),
                    "example.com".to_string(),
                    None,
                    None
                ),
                "https://example.com/.well-known/did.jsonl"
            ),
        ];

        for (did, expected_url) in test_cases {
            assert_eq!(did.to_url().unwrap().as_str(), expected_url);
        }
    }

    #[test]
    fn test_path_url_transformation() {
        let test_cases = vec![
            (
                TdwDid::new(
                    "abc123".to_string(),
                    "example.com".to_string(),
                    None,
                    Some("users".to_string())
                ),
                "whois",
                "https://example.com/users/whois"
            ),
            (
                TdwDid::new(
                    "abc123".to_string(),
                    "example.com".to_string(),
                    None,
                    None
                ),
                "whois",
                "https://example.com/whois"
            ),
        ];

        for (did, path, expected_url) in test_cases {
            assert_eq!(did.to_path_url(path).unwrap().as_str(), expected_url);
        }
    }
}