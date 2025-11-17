//! Public extension contracts (request signing, token leasing, rate limiting).
//!
//! The MVP crate intentionally exposes traits without concrete implementations so
//! downstream services can bring their own HTTP client, token cache, and rate
//! budgeting strategy. Future tasks will implement opinionated adapters in
//! separate crates without expanding the surface of `oauth2-broker` itself.

pub mod rate_limit;
pub mod request_signer;
pub mod token_lease;

pub use rate_limit::*;
pub use request_signer::*;
pub use token_lease::*;
