//! Provider strategy hooks that customize token exchanges.
//!
//! Implementations decorate outgoing token requests and normalize error mapping
//! without tying flows to any particular HTTP client.

// std
use std::collections::BTreeMap;
// self
use crate::{_prelude::*, provider::descriptor::GrantType};

/// Strategy hook that allows providers to decorate requests and classify errors.
///
/// Implementors are required to be `Send + Sync`, and the hooks intentionally use
/// crate-owned data types so downstream crates never depend on reqwest-specific
/// structures.  Override only what you need—`augment_token_request` has a default
/// no-op implementation.
pub trait ProviderStrategy: Send + Sync {
	/// Maps low-level HTTP/JSON errors into the broker taxonomy for a token request.
	fn classify_token_error(&self, ctx: &ProviderErrorContext) -> ProviderErrorKind;

	/// Gives providers a chance to add custom form parameters before dispatching.
	///
	/// The default implementation does nothing, which is enough for most providers.
	/// Override the hook when a provider requires extra fields (audience, resource,
	/// etc.).  The method works on a plain `BTreeMap` so implementations remain HTTP
	/// client agnostic.
	fn augment_token_request(&self, _grant: GrantType, _form: &mut BTreeMap<String, String>) {}
}

/// Canonical provider error categories used by strategies.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProviderErrorKind {
	/// Provider rejected the authorization grant (bad code/refresh token).
	InvalidGrant,
	/// Client authentication failed.
	InvalidClient,
	/// Requested scopes exceed what the token covers.
	InsufficientScope,
	/// Failure is temporary and should be retried.
	Transient,
}

/// Context passed to provider strategies when classifying token errors.
///
/// The struct intentionally keeps only primitive data (status codes, OAuth fields,
/// body preview) so strategies stay completely decoupled from any HTTP client
/// (e.g., reqwest).  Builders on the flows side populate the context before
/// invoking [`ProviderStrategy::classify_token_error`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProviderErrorContext {
	/// Grant type associated with the failing request.
	pub grant_type: GrantType,
	/// HTTP status code returned by the provider, when available.
	pub http_status: Option<u16>,
	/// Provider-supplied OAuth `error` field.
	pub oauth_error: Option<String>,
	/// Provider-supplied OAuth `error_description` field.
	pub error_description: Option<String>,
	/// Preview of the response body for non-JSON payloads.
	pub body_preview: Option<String>,
	/// Indicates whether the failure originated from the network/transport layer.
	pub network_error: bool,
}
impl ProviderErrorContext {
	const BODY_PREVIEW_LIMIT: usize = 256;

	/// Creates a new context scoped to the provided grant type.
	pub fn new(grant_type: GrantType) -> Self {
		Self {
			grant_type,
			http_status: None,
			oauth_error: None,
			error_description: None,
			body_preview: None,
			network_error: false,
		}
	}

	/// Convenience constructor for transport-level/network failures.
	pub fn network_failure(grant_type: GrantType) -> Self {
		let mut ctx = Self::new(grant_type);

		ctx.network_error = true;

		ctx
	}

	/// Overrides the network error flag.
	pub fn with_network_error(mut self, network_error: bool) -> Self {
		self.network_error = network_error;

		self
	}

	/// Adds an HTTP status code (e.g., 400, 401, 500).
	pub fn with_http_status(mut self, status: u16) -> Self {
		self.http_status = Some(status);

		self
	}

	/// Adds the OAuth error code string returned by the provider.
	pub fn with_oauth_error(mut self, error: impl Into<String>) -> Self {
		self.oauth_error = Some(error.into());

		self
	}

	/// Adds the OAuth `error_description` field.
	pub fn with_error_description(mut self, description: impl Into<String>) -> Self {
		self.error_description = Some(description.into());

		self
	}

	/// Adds a body preview for providers that return non-JSON payloads.
	pub fn with_body_preview(mut self, body: impl Into<String>) -> Self {
		self.body_preview = Some(truncate_preview(body.into()));

		self
	}
}

/// Default strategy that applies RFC-guided heuristics.
///
/// It prioritizes structured OAuth fields (`error`, `error_description`), then
/// falls back to body text hints, and finally the HTTP status code.  Network
/// failures are always treated as transient.
#[derive(Debug, Default)]
pub struct DefaultProviderStrategy;
impl Display for DefaultProviderStrategy {
	fn fmt(&self, f: &mut Formatter) -> FmtResult {
		f.write_str("default-provider-strategy")
	}
}
impl ProviderStrategy for DefaultProviderStrategy {
	fn classify_token_error(&self, ctx: &ProviderErrorContext) -> ProviderErrorKind {
		if ctx.network_error {
			return ProviderErrorKind::Transient;
		}

		if let Some(kind) =
			classify_oauth_error(ctx.oauth_error.as_deref(), ctx.error_description.as_deref())
		{
			return kind;
		}
		if let Some(kind) = classify_body(ctx.body_preview.as_deref()) {
			return kind;
		}

		classify_status(ctx.http_status)
	}
}

fn truncate_preview(body: String) -> String {
	if body.chars().count() <= ProviderErrorContext::BODY_PREVIEW_LIMIT {
		return body;
	}

	let mut buf = String::new();

	for (idx, ch) in body.chars().enumerate() {
		if idx >= ProviderErrorContext::BODY_PREVIEW_LIMIT {
			buf.push('…');

			break;
		}
		buf.push(ch);
	}

	buf
}

fn classify_oauth_error(
	oauth_error: Option<&str>,
	error_description: Option<&str>,
) -> Option<ProviderErrorKind> {
	oauth_error
		.and_then(match_exact_value)
		.or_else(|| error_description.and_then(match_exact_value))
		.or_else(|| classify_body(error_description))
}

fn match_exact_value(value: &str) -> Option<ProviderErrorKind> {
	if value.eq_ignore_ascii_case("invalid_grant") || value.eq_ignore_ascii_case("access_denied") {
		Some(ProviderErrorKind::InvalidGrant)
	} else if value.eq_ignore_ascii_case("invalid_client")
		|| value.eq_ignore_ascii_case("unauthorized_client")
	{
		Some(ProviderErrorKind::InvalidClient)
	} else if value.eq_ignore_ascii_case("invalid_scope")
		|| value.eq_ignore_ascii_case("insufficient_scope")
	{
		Some(ProviderErrorKind::InsufficientScope)
	} else if value.eq_ignore_ascii_case("temporarily_unavailable")
		|| value.eq_ignore_ascii_case("server_error")
	{
		Some(ProviderErrorKind::Transient)
	} else {
		None
	}
}

fn classify_body(body: Option<&str>) -> Option<ProviderErrorKind> {
	let body = body?;
	let lowered = body.to_ascii_lowercase();

	match lowered.as_str() {
		text if text.contains("invalid_grant") => Some(ProviderErrorKind::InvalidGrant),
		text if text.contains("invalid_client") => Some(ProviderErrorKind::InvalidClient),
		text if text.contains("insufficient_scope") || text.contains("invalid_scope") =>
			Some(ProviderErrorKind::InsufficientScope),
		text if text.contains("temporarily_unavailable") || text.contains("retry") =>
			Some(ProviderErrorKind::Transient),
		_ => None,
	}
}

fn classify_status(status: Option<u16>) -> ProviderErrorKind {
	match status {
		Some(400 | 404 | 410) => ProviderErrorKind::InvalidGrant,
		Some(401) => ProviderErrorKind::InvalidClient,
		Some(403) => ProviderErrorKind::InsufficientScope,
		Some(429) => ProviderErrorKind::Transient,
		Some(code) if code >= 500 => ProviderErrorKind::Transient,
		_ => ProviderErrorKind::Transient,
	}
}
