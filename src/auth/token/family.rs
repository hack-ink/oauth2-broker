//! Token family classification helpers (tenant/principal/provider).

// self
use crate::{
	_prelude::*,
	auth::{PrincipalId, ProviderId, TenantId},
};

/// Identifies a cohesive token family for a tenant/principal/provider tuple.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TokenFamily {
	/// Tenant identifier tied to all tokens in the family.
	pub tenant: TenantId,
	/// Principal identifier associated with the family.
	pub principal: PrincipalId,
	/// Optional provider identifier that minted the tokens.
	pub provider: Option<ProviderId>,
}
impl TokenFamily {
	/// Creates a family for the provided tenant and principal.
	pub fn new(tenant: TenantId, principal: PrincipalId) -> Self {
		Self { tenant, principal, provider: None }
	}
}
