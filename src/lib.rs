//! A pure resolver implementation for the DID:TDW (TrustDIDWeb) specification.
//!
//! This library provides functionality for resolving DID:TDW identifiers without any
//! creation or management capabilities. It is designed to be lightweight and focused
//! solely on resolution needs.

mod error;
mod types;
mod did;
mod resolver;
mod verification;

pub use error::ResolutionError;
pub use types::{
    DIDDocument,
    ResolutionResult,
    ResolutionMetadata,
    ResolutionOptions,
};
pub use did::TdwDid;
pub use resolver::{Resolver, resolve_did};

/// Resolves a DID:TDW identifier with optional resolution parameters
///
/// # Arguments
/// * `did` - The DID:TDW identifier to resolve
/// * `options` - Optional resolution parameters
///
/// # Example
/// ```no_run
/// use trustdidweb_resolver::{resolve_did, ResolutionOptions};
///
/// #[tokio::main]
/// async fn main() -> Result<(), Box<dyn std::error::Error>> {
///     let result = resolve_did(
///         "did:tdw:abc123:example.com",
///         None
///     ).await?;
///
///     println!("Resolved DID Document: {:?}", result.did_document);
///     Ok(())
/// }
/// ```
pub async fn resolve(
    did: &str,
    options: Option<ResolutionOptions>,
) -> Result<ResolutionResult, ResolutionError> {
    resolve_did(did, options).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_basic_resolution() {
        // TODO: Add integration tests
    }
}