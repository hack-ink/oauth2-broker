// std
use std::iter::IntoIterator;
// self
use crate::{
	_prelude::*,
	auth::ProviderId,
	provider::{
		ClientAuthMethod, GrantType, ProviderDescriptor, ProviderEndpoints, ProviderQuirks,
		SupportedGrants,
	},
};

/// Errors raised while constructing or validating descriptors.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, ThisError)]
pub enum ProviderDescriptorError {
	/// Authorization endpoint is required for Authorization Code flows.
	#[error("Missing authorization endpoint.")]
	MissingAuthorizationEndpoint,
	/// Token endpoint is mandatory for all flows.
	#[error("Missing token endpoint.")]
	MissingTokenEndpoint,
	/// At least one grant must be supported.
	#[error("Descriptor must enable at least one grant type.")]
	NoSupportedGrants,
	/// PKCE requirement implies Authorization Code support.
	#[error("The `pkce_required` flag requires enabling the authorization_code grant.")]
	PkceRequiredWithoutAuthorizationCode,
	/// Endpoints must use HTTPS.
	#[error("The {endpoint} endpoint must use HTTPS: {url}.")]
	InsecureEndpoint {
		/// Which endpoint failed validation.
		endpoint: &'static str,
		/// Endpoint URL that failed validation.
		url: String,
	},
	/// Reject scope delimiters that are control characters.
	#[error("Scope delimiter must be a printable character.")]
	InvalidScopeDelimiter {
		/// Invalid delimiter that was supplied.
		delimiter: char,
	},
}

/// Builder for [`ProviderDescriptor`] values.
#[derive(Debug)]
pub struct ProviderDescriptorBuilder {
	/// Identifier for the descriptor being constructed.
	pub id: ProviderId,
	/// Optional authorization endpoint (required for Authorization Code flows).
	pub authorization_endpoint: Option<Url>,
	/// Token endpoint used for exchanges and refreshes.
	pub token_endpoint: Option<Url>,
	/// Optional revocation endpoint.
	pub revocation_endpoint: Option<Url>,
	/// Grants enabled for the provider.
	pub supported_grants: SupportedGrants,
	/// Preferred client authentication method for the token endpoint.
	pub preferred_client_auth_method: ClientAuthMethod,
	/// Provider-specific quirks.
	pub quirks: ProviderQuirks,
}
impl ProviderDescriptorBuilder {
	/// Creates a new builder seeded with the provided identifier.
	pub fn new(id: ProviderId) -> Self {
		Self {
			id,
			authorization_endpoint: None,
			token_endpoint: None,
			revocation_endpoint: None,
			supported_grants: SupportedGrants::default(),
			preferred_client_auth_method: ClientAuthMethod::default(),
			quirks: ProviderQuirks::default(),
		}
	}

	/// Sets the authorization endpoint.
	pub fn authorization_endpoint(mut self, url: Url) -> Self {
		self.authorization_endpoint = Some(url);

		self
	}

	/// Sets the token endpoint.
	pub fn token_endpoint(mut self, url: Url) -> Self {
		self.token_endpoint = Some(url);

		self
	}

	/// Sets the optional revocation endpoint.
	pub fn revocation_endpoint(mut self, url: Url) -> Self {
		self.revocation_endpoint = Some(url);

		self
	}

	/// Marks a single grant type as supported.
	pub fn support_grant(mut self, grant: GrantType) -> Self {
		self.supported_grants = self.supported_grants.enable(grant);

		self
	}

	/// Marks multiple grants as supported.
	pub fn support_grants<I>(mut self, grants: I) -> Self
	where
		I: IntoIterator<Item = GrantType>,
	{
		for grant in grants.into_iter() {
			self.supported_grants = self.supported_grants.enable(grant);
		}

		self
	}

	/// Overrides the preferred client authentication method.
	pub fn preferred_client_auth_method(mut self, method: ClientAuthMethod) -> Self {
		self.preferred_client_auth_method = method;

		self
	}

	/// Overrides the provider quirks.
	pub fn quirks(mut self, quirks: ProviderQuirks) -> Self {
		self.quirks = quirks;

		self
	}

	/// Consumes the builder and validates the resulting descriptor.
	pub fn build(self) -> Result<ProviderDescriptor, ProviderDescriptorError> {
		let authorization = self
			.authorization_endpoint
			.ok_or(ProviderDescriptorError::MissingAuthorizationEndpoint)?;
		let token = self.token_endpoint.ok_or(ProviderDescriptorError::MissingTokenEndpoint)?;
		let endpoints =
			ProviderEndpoints { authorization, token, revocation: self.revocation_endpoint };
		let descriptor = ProviderDescriptor {
			id: self.id,
			endpoints,
			supported_grants: self.supported_grants,
			preferred_client_auth_method: self.preferred_client_auth_method,
			quirks: self.quirks,
		};

		descriptor.validate()?;

		Ok(descriptor)
	}
}

impl ProviderDescriptor {
	/// Validates invariants for the descriptor.
	fn validate(&self) -> Result<(), ProviderDescriptorError> {
		if self.supported_grants.is_empty() {
			return Err(ProviderDescriptorError::NoSupportedGrants);
		}
		if self.quirks.pkce_required && !self.supports(GrantType::AuthorizationCode) {
			return Err(ProviderDescriptorError::PkceRequiredWithoutAuthorizationCode);
		}

		validate_endpoint("authorization", &self.endpoints.authorization)?;
		validate_endpoint("token", &self.endpoints.token)?;

		if let Some(revocation) = self.endpoints.revocation.as_ref() {
			validate_endpoint("revocation", revocation)?;
		}

		validate_scope_delimiter(self.quirks.scope_delimiter)?;

		Ok(())
	}
}

fn validate_endpoint(name: &'static str, url: &Url) -> Result<(), ProviderDescriptorError> {
	if url.scheme() != "https" {
		Err(ProviderDescriptorError::InsecureEndpoint { endpoint: name, url: url.to_string() })
	} else {
		Ok(())
	}
}

fn validate_scope_delimiter(delimiter: char) -> Result<(), ProviderDescriptorError> {
	if delimiter.is_control() {
		Err(ProviderDescriptorError::InvalidScopeDelimiter { delimiter })
	} else {
		Ok(())
	}
}
