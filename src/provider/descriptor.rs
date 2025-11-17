//! Provider descriptor data structures and helpers shared by all flows.
//!
//! The module exposes validated metadata, supporting builder utilities, and
//! grant-specific helpers so providers can describe their capabilities in a
//! transport-agnostic way.

/// Builder API for assembling provider descriptors.
pub mod builder;
/// Grant helpers wired into provider descriptors.
pub mod grant;
/// Provider-specific quirk toggles.
pub mod quirks;

pub use builder::*;
pub use grant::*;
pub use quirks::*;

// self
use crate::{_prelude::*, auth::ProviderId};

/// Preferred client authentication modes for token endpoint calls.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientAuthMethod {
	#[default]
	/// HTTP Basic with `client_id`/`client_secret`.
	ClientSecretBasic,
	/// Form POST body parameters for `client_id`/`client_secret`.
	ClientSecretPost,
	/// Public clients that prove possession via PKCE.
	NoneWithPkce,
}

/// Endpoint set declared by a provider descriptor.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderEndpoints {
	/// Authorization endpoint used by the Authorization Code flow.
	pub authorization: Url,
	/// Token endpoint used for exchanges and refreshes.
	pub token: Url,
	/// Optional revocation endpoint.
	pub revocation: Option<Url>,
}

/// Immutable provider descriptor consumed by flows.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderDescriptor {
	/// Descriptor identifier.
	pub id: ProviderId,
	/// Endpoint definitions exposed by the provider.
	pub endpoints: ProviderEndpoints,
	/// Supported grant flags.
	pub supported_grants: SupportedGrants,
	/// Preferred client authentication mechanism.
	pub preferred_client_auth_method: ClientAuthMethod,
	/// Provider-specific quirks.
	pub quirks: ProviderQuirks,
}
impl ProviderDescriptor {
	/// Creates a new builder for the provided identifier.
	pub fn builder(id: ProviderId) -> ProviderDescriptorBuilder {
		ProviderDescriptorBuilder::new(id)
	}

	/// Checks whether the descriptor supports a given grant.
	pub fn supports(&self, grant: GrantType) -> bool {
		self.supported_grants.supports(grant)
	}
}
