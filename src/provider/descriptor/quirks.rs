// self
use crate::_prelude::*;

/// Provider-specific quirks that influence how flows behave.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ProviderQuirks {
	/// Indicates whether PKCE must be supplied even for confidential clients.
	pub pkce_required: bool,
	/// Indicates whether redirect URIs must match exactly (instead of using a prefix match).
	pub exact_redirect_match: bool,
	/// Character used to join scopes when constructing `scope` parameters.
	pub scope_delimiter: char,
}
impl Default for ProviderQuirks {
	fn default() -> Self {
		Self { pkce_required: false, exact_redirect_match: true, scope_delimiter: ' ' }
	}
}
