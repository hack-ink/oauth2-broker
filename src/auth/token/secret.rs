//! Secure token secret wrapper that redacts sensitive material.

// self
use crate::_prelude::*;

/// Redacted token secret wrapper keeping sensitive material out of logs.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenSecret(String);
impl TokenSecret {
	/// Wraps a new secret string.
	pub fn new(value: impl Into<String>) -> Self {
		Self(value.into())
	}

	/// Returns the inner token value. Callers must avoid logging this string.
	pub fn expose(&self) -> &str {
		&self.0
	}
}
impl AsRef<str> for TokenSecret {
	fn as_ref(&self) -> &str {
		self.expose()
	}
}
impl Debug for TokenSecret {
	fn fmt(&self, f: &mut Formatter) -> FmtResult {
		f.debug_tuple("TokenSecret").field(&"<redacted>").finish()
	}
}
impl Display for TokenSecret {
	fn fmt(&self, f: &mut Formatter) -> FmtResult {
		f.write_str("<redacted>")
	}
}

#[cfg(test)]
mod tests {
	// self
	use super::*;

	#[test]
	fn secret_formatters_redact() {
		let secret = TokenSecret::new("super-secret");

		assert_eq!(format!("{secret:?}"), "TokenSecret(\"<redacted>\")");
		assert_eq!(format!("{secret}"), "<redacted>");
	}
}
