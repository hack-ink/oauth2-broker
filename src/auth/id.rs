//! Strongly typed identifiers enforced across the broker domain.

// std
use std::{borrow::Borrow, ops::Deref};
// self
use crate::_prelude::*;

macro_rules! def_id {
	($name:ident, $doc:literal, $kind:literal) => {
		#[doc = $doc]
		#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
		#[serde(try_from = "String", into = "String")]
		pub struct $name(String);
		impl $name {
			/// Creates a new identifier after validation.
			pub fn new(value: impl AsRef<str>) -> Result<Self, IdentifierError> {
				let view = value.as_ref();

				validate_view($kind, view)?;

				Ok(Self(view.to_owned()))
			}
		}
		impl Deref for $name {
			type Target = str;

			fn deref(&self) -> &Self::Target {
				&self.0
			}
		}
		impl AsRef<str> for $name {
			fn as_ref(&self) -> &str {
				&self.0
			}
		}
		impl From<$name> for String {
			fn from(value: $name) -> Self {
				value.0
			}
		}
		impl TryFrom<String> for $name {
			type Error = IdentifierError;

			fn try_from(value: String) -> Result<Self, Self::Error> {
				validate_view($kind, &value)?;

				Ok(Self(value))
			}
		}
		impl Borrow<str> for $name {
			fn borrow(&self) -> &str {
				&self.0
			}
		}
		impl Debug for $name {
			fn fmt(&self, f: &mut Formatter) -> FmtResult {
				write!(f, concat!($kind, "({})"), self.0)
			}
		}
		impl Display for $name {
			fn fmt(&self, f: &mut Formatter) -> FmtResult {
				f.write_str(&self.0)
			}
		}
		impl FromStr for $name {
			type Err = IdentifierError;

			fn from_str(s: &str) -> Result<Self, Self::Err> {
				Self::new(s)
			}
		}
	};
}

const IDENTIFIER_MAX_LEN: usize = 128;

/// Error returned when identifier validation fails.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, ThisError)]
pub enum IdentifierError {
	/// The identifier was empty or whitespace.
	#[error("{kind} identifier cannot be empty.")]
	Empty {
		/// Kind of identifier (tenant, principal, provider).
		kind: &'static str,
	},
	/// The identifier contains whitespace characters.
	#[error("{kind} identifier contains whitespace.")]
	ContainsWhitespace {
		/// Kind of identifier (tenant, principal, provider).
		kind: &'static str,
	},
	/// The identifier exceeded the allowed character count.
	#[error("{kind} identifier exceeds {max} characters.")]
	TooLong {
		/// Kind of identifier (tenant, principal, provider).
		kind: &'static str,
		/// Maximum permitted character count.
		max: usize,
	},
}

def_id! { TenantId, "Unique identifier for a broker tenant.", "Tenant" }
def_id! { PrincipalId, "Unique identifier for a broker principal.", "Principal" }
def_id! { ProviderId, "Identifier for an OAuth provider descriptor.", "Provider" }

fn validate_view(kind: &'static str, view: &str) -> Result<(), IdentifierError> {
	if view.is_empty() {
		return Err(IdentifierError::Empty { kind });
	}
	if view.chars().any(char::is_whitespace) {
		return Err(IdentifierError::ContainsWhitespace { kind });
	}
	if view.len() > IDENTIFIER_MAX_LEN {
		return Err(IdentifierError::TooLong { kind, max: IDENTIFIER_MAX_LEN });
	}

	Ok(())
}

#[cfg(test)]
mod tests {
	// self
	use super::*;

	#[test]
	fn identifiers_trim_and_validate() {
		assert!(TenantId::new(" tenant-123").is_err(), "Leading whitespace must be rejected.");
		assert!(TenantId::new("tenant-123 ").is_err(), "Trailing whitespace must be rejected.");

		let tenant =
			TenantId::new("tenant-123").expect("Tenant fixture should be considered valid.");

		assert_eq!(tenant.as_ref(), "tenant-123");
		assert!(PrincipalId::new("").is_err());
		assert!(ProviderId::new("with space").is_err());
	}

	#[test]
	fn serde_round_trip_enforces_validation() {
		let payload = "\"tenant-42\"";
		let tenant: TenantId =
			serde_json::from_str(payload).expect("Tenant should deserialize successfully.");

		assert_eq!(tenant.as_ref(), "tenant-42");
		assert!(serde_json::from_str::<TenantId>("\"with space\"").is_err());
		assert!(serde_json::from_str::<TenantId>("\" tenant-42\"").is_err());
	}

	#[test]
	fn unicode_whitespace_and_length_limits() {
		let nbsp = format!("tenant{}id", '\u{00A0}');

		assert!(TenantId::new(&nbsp).is_err());

		let exact = "a".repeat(IDENTIFIER_MAX_LEN);

		TenantId::new(&exact).expect("Exact length should succeed.");

		let too_long = "a".repeat(IDENTIFIER_MAX_LEN + 1);

		assert!(TenantId::new(&too_long).is_err());
	}

	#[test]
	fn borrow_supports_fast_lookup() {
		let map: HashMap<TenantId, u8> = HashMap::from_iter([(
			TenantId::new("tenant-123").expect("Tenant used for lookup should be valid."),
			7_u8,
		)]);

		assert_eq!(map.get("tenant-123"), Some(&7));
	}
}
