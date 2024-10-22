# trustdidweb-resolver

A pure resolver implementation for the DID:TDW (TrustDIDWeb) specification. This library provides functionality for resolving DID:TDW identifiers without any creation or management capabilities.

## Features

- Pure resolution implementation focusing on efficiency and minimal dependencies
- Support for version and time-based resolution
- DID URL resolution including `/whois` support
- Comprehensive verification of DID Log entries
- Async/await support for efficient network operations

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
trustdidweb-resolver = "0.1"
```

### Basic Example

```rust
use trustdidweb_resolver::{resolve, ResolutionOptions};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Simple resolution
    let result = resolve(
        "did:tdw:abc123:example.com",
        None
    ).await?;

    println!("Resolved DID Document: {:?}", result.did_document);

    // Resolution with specific version
    let result_with_version = resolve(
        "did:tdw:abc123:example.com",
        Some(ResolutionOptions {
            version_id: Some("2-xyz789".to_string()),
            version_time: None,
        })
    ).await?;

    println!("Resolved specific version: {:?}", result_with_version.did_document);

    Ok(())
}
```

## Feature Flags

- `default` - Includes all basic resolution functionality
- (Future: add feature flags for optional resolution capabilities)

## Testing

Run tests using:

```bash
cargo test
```

## License

Licensed under Apache License, Version 2.0 ([LICENSE](LICENSE) or http://www.apache.org/licenses/LICENSE-2.0)