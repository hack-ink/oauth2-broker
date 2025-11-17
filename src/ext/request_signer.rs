//! Request signing contracts that let downstream crates attach broker-issued
//! tokens to arbitrary HTTP clients.

// self
use crate::auth::TokenRecord;

/// Describes how to attach a [`TokenRecord`] to an outbound request without
/// constraining the HTTP client type.
///
/// The trait is intentionally generic over both the request and error types so
/// implementers can integrate with any client builder (`reqwest`, `surf`, a
/// bespoke SDK, etc.) while keeping `oauth2-broker` free of those dependencies.
pub trait RequestSignerExt<Request, Error>
where
	Self: Send + Sync,
{
	/// Consumes (or clones) the provided request and injects authorization state
	/// derived from the [`TokenRecord`].
	fn attach_token(&self, request: Request, record: &TokenRecord) -> Result<Request, Error>;
}
