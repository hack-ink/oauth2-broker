// crates.io
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::{Rng, distr::Alphanumeric};
use sha2::{Digest, Sha256};
// self
use crate::{
	_prelude::*,
	auth::{PrincipalId, ScopeSet, TenantId},
	flows::common,
	provider::ProviderDescriptor,
};

const STATE_LEN: usize = 32;
const PKCE_VERIFIER_LEN: usize = 64;

/// Supported PKCE challenge methods surfaced via [`AuthorizationSession`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PkceCodeChallengeMethod {
	/// SHA-256 based PKCE (RFC 7636 S256).
	S256,
}
impl PkceCodeChallengeMethod {
	/// Returns the RFC 7636 identifier for the challenge method.
	pub fn as_str(self) -> &'static str {
		match self {
			PkceCodeChallengeMethod::S256 => "S256",
		}
	}
}

/// Authorization Code + PKCE handshake metadata returned by [`Broker::start_authorization`].
#[derive(Clone)]
pub struct AuthorizationSession {
	/// Tenant identifier tied to the session.
	pub tenant: TenantId,
	/// Principal identifier tied to the session.
	pub principal: PrincipalId,
	/// Requested scope set (prior to any provider overrides during exchange).
	pub scope: ScopeSet,
	/// Opaque state value that must round-trip via the redirect handler.
	pub state: String,
	/// Redirect URI supplied when constructing the authorize URL.
	pub redirect_uri: Url,
	/// Fully-formed HTTPS authorize URL that callers should send end-users to.
	pub authorize_url: Url,
	pkce: PkcePair,
}
impl AuthorizationSession {
	pub(super) fn new(
		tenant: TenantId,
		principal: PrincipalId,
		scope: ScopeSet,
		redirect_uri: Url,
		authorize_url: Url,
		state: String,
		pkce: PkcePair,
	) -> Self {
		Self { tenant, principal, scope, state, redirect_uri, authorize_url, pkce }
	}

	/// PKCE code challenge derived from the secret verifier.
	pub fn code_challenge(&self) -> &str {
		&self.pkce.challenge
	}

	/// PKCE challenge method (currently always `S256`).
	pub fn code_challenge_method(&self) -> PkceCodeChallengeMethod {
		self.pkce.method
	}

	/// Validates the returned `state` parameter after the authorization redirect.
	pub fn validate_state(&self, returned_state: &str) -> Result<()> {
		if returned_state == self.state {
			Ok(())
		} else {
			Err(Error::InvalidGrant { reason: "Authorization state mismatch.".into() })
		}
	}

	pub(super) fn into_exchange_parts(self) -> (TenantId, PrincipalId, ScopeSet, Url, PkcePair) {
		let AuthorizationSession { tenant, principal, scope, redirect_uri, pkce, .. } = self;

		(tenant, principal, scope, redirect_uri, pkce)
	}
}
impl Debug for AuthorizationSession {
	fn fmt(&self, f: &mut Formatter) -> FmtResult {
		f.debug_struct("AuthorizationSession")
			.field("tenant", &self.tenant)
			.field("principal", &self.principal)
			.field("scope", &self.scope)
			.field("state", &self.state)
			.field("redirect_uri", &self.redirect_uri)
			.field("authorize_url", &self.authorize_url)
			.field("code_challenge", &self.pkce.challenge)
			.field("code_challenge_method", &self.pkce.method)
			.finish()
	}
}

#[derive(Clone)]
pub(super) struct PkcePair {
	pub(super) verifier: String,
	challenge: String,
	method: PkceCodeChallengeMethod,
}
impl PkcePair {
	pub(super) fn generate() -> Self {
		let verifier = random_string(PKCE_VERIFIER_LEN);
		let challenge = compute_pkce_challenge(&verifier);

		Self { verifier, challenge, method: PkceCodeChallengeMethod::S256 }
	}
}

pub(super) fn build_session(
	descriptor: &ProviderDescriptor,
	client_id: &str,
	tenant: TenantId,
	principal: PrincipalId,
	scope: ScopeSet,
	redirect_uri: Url,
) -> AuthorizationSession {
	let state = random_string(STATE_LEN);
	let pkce = PkcePair::generate();
	let authorize_url =
		build_authorize_url(descriptor, client_id, &redirect_uri, &scope, &state, &pkce);

	AuthorizationSession::new(tenant, principal, scope, redirect_uri, authorize_url, state, pkce)
}

fn build_authorize_url(
	descriptor: &ProviderDescriptor,
	client_id: &str,
	redirect_uri: &Url,
	scope: &ScopeSet,
	state: &str,
	pkce: &PkcePair,
) -> Url {
	let mut url = descriptor.endpoints.authorization.clone();
	let mut pairs = url.query_pairs_mut();

	pairs.append_pair("response_type", "code");
	pairs.append_pair("client_id", client_id);
	pairs.append_pair("redirect_uri", redirect_uri.as_str());

	if let Some(scope_value) = common::format_scope(scope, descriptor.quirks.scope_delimiter) {
		pairs.append_pair("scope", &scope_value);
	}

	pairs.append_pair("state", state);
	pairs.append_pair("code_challenge", &pkce.challenge);
	pairs.append_pair("code_challenge_method", pkce.method.as_str());

	drop(pairs);

	url
}

fn random_string(len: usize) -> String {
	rand::rng().sample_iter(Alphanumeric).take(len).map(char::from).collect()
}

fn compute_pkce_challenge(verifier: &str) -> String {
	let mut hasher = Sha256::new();
	hasher.update(verifier.as_bytes());
	let digest = hasher.finalize();
	URL_SAFE_NO_PAD.encode(digest)
}

#[cfg(test)]
mod tests {
	// self
	use super::*;

	#[test]
	fn state_validation_errors_on_mismatch() {
		let session = AuthorizationSession::new(
			TenantId::new("tenant").expect("Tenant fixture should be valid for PKCE tests."),
			PrincipalId::new("principal")
				.expect("Principal fixture should be valid for PKCE tests."),
			ScopeSet::new(Vec::<&str>::new()).expect("Failed to build empty scope set for test."),
			Url::parse("https://example.com/cb")
				.expect("Redirect URL fixture should parse successfully."),
			Url::parse("https://example.com/auth?state=abc")
				.expect("Authorization URL fixture should parse successfully."),
			"expected".into(),
			PkcePair::generate(),
		);

		assert!(session.validate_state("expected").is_ok());

		let err = session.validate_state("other").expect_err("State mismatch should fail.");

		assert!(matches!(err, Error::InvalidGrant { .. }));
	}
}
