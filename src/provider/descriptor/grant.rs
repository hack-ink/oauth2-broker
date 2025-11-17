// self
use crate::_prelude::*;

/// OAuth 2.0 grant types supported by the broker.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantType {
	/// Authorization Code grant (PKCE recommended).
	AuthorizationCode,
	/// Refresh Token grant for long-lived sessions.
	RefreshToken,
	/// Client Credentials grant for app-only tokens.
	ClientCredentials,
}
impl GrantType {
	/// Returns the RFC 6749 identifier for the grant type.
	pub fn as_str(self) -> &'static str {
		match self {
			GrantType::AuthorizationCode => "authorization_code",
			GrantType::RefreshToken => "refresh_token",
			GrantType::ClientCredentials => "client_credentials",
		}
	}
}
impl Display for GrantType {
	fn fmt(&self, f: &mut Formatter) -> FmtResult {
		f.write_str(self.as_str())
	}
}

/// Collection of grant flags wired into the descriptor.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SupportedGrants {
	/// Indicates whether the Authorization Code grant is enabled.
	pub authorization_code: bool,
	/// Indicates whether the Refresh Token grant is enabled.
	pub refresh_token: bool,
	/// Indicates whether the Client Credentials grant is enabled.
	pub client_credentials: bool,
}
impl SupportedGrants {
	/// Returns true if the provided grant is supported.
	pub fn supports(self, grant: GrantType) -> bool {
		match grant {
			GrantType::AuthorizationCode => self.authorization_code,
			GrantType::RefreshToken => self.refresh_token,
			GrantType::ClientCredentials => self.client_credentials,
		}
	}

	/// Marks a grant as supported.
	pub fn enable(mut self, grant: GrantType) -> Self {
		match grant {
			GrantType::AuthorizationCode => self.authorization_code = true,
			GrantType::RefreshToken => self.refresh_token = true,
			GrantType::ClientCredentials => self.client_credentials = true,
		}

		self
	}

	/// Returns true when no grants are enabled.
	pub fn is_empty(self) -> bool {
		!self.authorization_code && !self.refresh_token && !self.client_credentials
	}
}
