//! Provider-facing descriptors (data) and strategies (behavior).
//!
//! `descriptor` exposes validated metadata (`ProviderDescriptor`) covering HTTPS-only
//! endpoints, supported grant flags, client authentication preferences, and
//! provider quirks (PKCE requirement, redirect semantics, scope delimiter).
//! `strategy` defines [`ProviderStrategy`], an HTTP-client-agnostic hook used by flows
//! to augment outgoing token requests and map responses into the broker error taxonomy.

pub mod descriptor;
pub mod strategy;

pub use descriptor::*;
pub use strategy::*;
