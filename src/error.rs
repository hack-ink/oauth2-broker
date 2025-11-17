//! Broker-level error types shared across flows, providers, and stores.

// self
use crate::_prelude::*;

/// Broker-wide result type alias returning [`Error`] by default.
pub type Result<T, E = Error> = std::result::Result<T, E>;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Canonical broker error exposed by public APIs.
#[derive(Debug, ThisError)]
pub enum Error {
	/// Storage-layer failure.
	#[error("{0}")]
	Storage(
		#[from]
		#[source]
		crate::store::StoreError,
	),
	/// Local configuration problem.
	#[error(transparent)]
	Config(#[from] ConfigError),
	/// Temporary upstream failure; retry with backoff.
	#[error(transparent)]
	Transient(#[from] TransientError),
	/// Transport failure (DNS, TCP, TLS).
	#[error(transparent)]
	Transport(#[from] TransportError),

	/// Requested scopes exceed what was granted.
	#[error("Token lacks the required scopes: {reason}.")]
	InsufficientScope {
		/// Provider- or broker-supplied reason string.
		reason: String,
	},
	/// Provider rejected the grant (e.g., bad code or refresh token).
	#[error("Provider rejected the grant: {reason}.")]
	InvalidGrant {
		/// Provider- or broker-supplied reason string.
		reason: String,
	},
	/// Client authentication failed or credentials are malformed.
	#[error("Client authentication failed: {reason}.")]
	InvalidClient {
		/// Provider- or broker-supplied reason string.
		reason: String,
	},
	/// Token has been revoked and must not be reused.
	#[error("Token has been revoked.")]
	Revoked,
}

/// Configuration and validation failures raised by the broker.
#[derive(Debug, ThisError)]
pub enum ConfigError {
	/// HTTP client could not be constructed.
	#[error("HTTP client could not be constructed.")]
	HttpClientBuild {
		/// Underlying transport builder failure.
		#[source]
		source: BoxError,
	},
	/// HTTP request construction failed.
	#[error(transparent)]
	HttpRequest(#[from] oauth2::http::Error),
	/// Provider descriptor contains an invalid URL.
	#[error("Descriptor contains an invalid URL.")]
	InvalidDescriptor {
		/// Underlying parsing failure.
		#[source]
		source: oauth2::url::ParseError,
	},
	/// Redirect URI cannot be parsed.
	#[error("Redirect URI is invalid.")]
	InvalidRedirect {
		/// Underlying parsing failure.
		#[source]
		source: oauth2::url::ParseError,
	},

	/// Descriptor does not enable the requested grant.
	#[error("Descriptor `{descriptor}` does not enable the {grant} grant.")]
	UnsupportedGrant {
		/// Provider identifier string.
		descriptor: String,
		/// Disabled grant label.
		grant: &'static str,
	},
	/// Cached record is missing a refresh secret.
	#[error("Cached token record is missing a refresh token.")]
	MissingRefreshToken,
	/// Request scopes cannot be normalized.
	#[error("Requested scopes are invalid.")]
	InvalidScope(#[from] crate::auth::ScopeValidationError),
	/// Token record builder validation failed.
	#[error("Unable to build token record.")]
	TokenBuild(#[from] crate::auth::TokenRecordBuilderError),
	/// Token endpoint response omitted `expires_in`.
	#[error("Token endpoint response is missing expires_in.")]
	MissingExpiresIn,
	/// Token endpoint returned an excessively large `expires_in`.
	#[error("The expires_in value exceeds the supported range.")]
	ExpiresInOutOfRange,
	/// Token endpoint returned a non-positive duration.
	#[error("The expires_in value must be positive.")]
	NonPositiveExpiresIn,
	/// Provider changed scopes during the exchange.
	#[error("Token endpoint changed scopes during the {grant} grant.")]
	ScopesChanged {
		/// Grant label.
		grant: &'static str,
	},
}
impl ConfigError {
	/// Wraps a transport's builder failure inside [`ConfigError`].
	pub fn http_client_build(src: impl 'static + Send + Sync + std::error::Error) -> Self {
		Self::HttpClientBuild { source: Box::new(src) }
	}
}
impl From<reqwest::Error> for ConfigError {
	fn from(e: reqwest::Error) -> Self {
		Self::http_client_build(e)
	}
}

/// Temporary failure variants (safe to retry).
#[derive(Debug, ThisError)]
pub enum TransientError {
	/// Provider returned an unexpected but non-fatal response.
	#[error("Token endpoint returned an unexpected response: {message}.")]
	TokenEndpoint {
		/// Provider- or broker-supplied message summarizing the failure.
		message: String,
		/// HTTP status code, when available.
		status: Option<u16>,
		/// Retry-After hint from upstream, if supplied.
		retry_after: Option<Duration>,
	},
	/// Token endpoint responded with malformed JSON that could not be parsed.
	#[error("Token endpoint returned malformed JSON.")]
	TokenResponseParse {
		/// Structured parsing failure.
		#[source]
		source: serde_path_to_error::Error<serde_json::error::Error>,
		/// HTTP status code, when available.
		status: Option<u16>,
	},
}
/// Transport-level failures (network, IO).
#[derive(Debug, ThisError)]
pub enum TransportError {
	/// Underlying HTTP client reported a network failure.
	#[error("Network error occurred while calling the token endpoint.")]
	Network {
		/// Transport-specific network error.
		#[source]
		source: BoxError,
	},
	/// Underlying IO failure surfaced during transport.
	#[error("I/O error occurred while calling the token endpoint.")]
	Io(#[from] std::io::Error),
}
impl TransportError {
	/// Wraps a transport-specific network error.
	pub fn network(src: impl 'static + Send + Sync + std::error::Error) -> Self {
		Self::Network { source: Box::new(src) }
	}
}
impl From<ReqwestError> for TransportError {
	fn from(e: ReqwestError) -> Self {
		Self::network(e)
	}
}
