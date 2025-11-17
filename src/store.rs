//! Storage contracts and built-in store implementations for broker token records.

pub mod file;
pub mod memory;

pub use file::FileStore;
pub use memory::MemoryStore;

// self
use crate::{
	_prelude::*,
	auth::{ScopeSet, TokenFamily, TokenRecord},
};

/// Persistence contract for broker-issued tokens.
pub type StoreFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, StoreError>> + 'a + Send>>;

/// Storage backend contract implemented by broker token stores.
pub trait BrokerStore
where
	Self: Send + Sync,
{
	/// Persists or replaces a token record for the provided family + scope.
	fn save(&self, record: TokenRecord) -> StoreFuture<'_, ()>;

	/// Fetches the record associated with the family + scope, if present.
	fn fetch<'a>(
		&'a self,
		family: &'a TokenFamily,
		scope: &'a ScopeSet,
	) -> StoreFuture<'a, Option<TokenRecord>>;

	/// Atomically rotates a refresh token if the expected secret matches.
	fn compare_and_swap_refresh<'a>(
		&'a self,
		family: &'a TokenFamily,
		scope: &'a ScopeSet,
		expected_refresh: Option<&'a str>,
		replacement: TokenRecord,
	) -> StoreFuture<'a, CompareAndSwapOutcome>;

	/// Marks a record as revoked at the provided instant.
	fn revoke<'a>(
		&'a self,
		family: &'a TokenFamily,
		scope: &'a ScopeSet,
		instant: OffsetDateTime,
	) -> StoreFuture<'a, Option<TokenRecord>>;
}

/// Result of a refresh-token compare-and-swap attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CompareAndSwapOutcome {
	/// The refresh secret matched the expected value and the record was updated.
	Updated,
	/// The record exists but the expected refresh secret did not match.
	RefreshMismatch,
	/// No record matched the provided family + scope.
	Missing,
}

/// Error type produced by [`BrokerStore`] implementations.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ThisError)]
pub enum StoreError {
	/// Serialization failures (e.g., serde/bincode) surfaced by the backend.
	#[error("Serialization error: {message}.")]
	Serialization {
		/// Human-readable error payload.
		message: String,
	},
	/// Backend-level failure for the storage engine.
	#[error("Backend failure: {message}.")]
	Backend {
		/// Human-readable error payload.
		message: String,
	},
}

/// Unique key identifying a stored token record.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct StoreKey {
	/// Token family component.
	pub family: TokenFamily,
	/// Scope fingerprint used for partitioning.
	pub scope_fingerprint: String,
}
impl StoreKey {
	/// Builds a key using the provided family and scope fingerprint.
	pub fn new(family: &TokenFamily, scope: &ScopeSet) -> Self {
		Self { family: family.clone(), scope_fingerprint: scope.fingerprint() }
	}
}

#[cfg(test)]
mod tests {
	// self
	use super::*;
	use crate::{
		auth::{PrincipalId, ScopeSet, TenantId},
		error::Error,
	};
	use std::error::Error as StdError;

	#[test]
	fn store_error_converts_into_broker_error_with_source() {
		let store_error = StoreError::Backend { message: "database unreachable".into() };
		let broker_error: Error = store_error.clone().into();

		assert!(matches!(broker_error, Error::Storage(_)));
		assert!(broker_error.to_string().contains("database unreachable"));

		let source = StdError::source(&broker_error)
			.expect("Broker error should expose the original store error as its source.");

		assert_eq!(source.to_string(), store_error.to_string());
	}

	#[test]
	fn store_key_uses_scope_fingerprint() {
		let tenant = TenantId::new("tenant-1").expect("Tenant fixture should be valid.");
		let principal =
			PrincipalId::new("principal-1").expect("Principal fixture should be valid.");
		let family = TokenFamily::new(tenant, principal);
		let scope_a =
			ScopeSet::new(["profile", "email"]).expect("First scope fixture should be valid.");
		let scope_b =
			ScopeSet::new(["email", "profile"]).expect("Second scope fixture should be valid.");
		let key_a = StoreKey::new(&family, &scope_a);
		let key_b = StoreKey::new(&family, &scope_b);

		assert_eq!(key_a.scope_fingerprint, key_b.scope_fingerprint);
		assert_eq!(key_a.family, key_b.family);
		assert_eq!(key_a, key_b);
	}

	#[test]
	fn compare_and_swap_outcome_can_be_serialized() {
		let payload = serde_json::to_string(&CompareAndSwapOutcome::Updated)
			.expect("CompareAndSwapOutcome should serialize to JSON.");

		assert_eq!(payload, "\"Updated\"");

		let round_trip: CompareAndSwapOutcome = serde_json::from_str(&payload)
			.expect("Serialized outcome should deserialize from JSON.");

		assert_eq!(round_trip, CompareAndSwapOutcome::Updated);
	}
}
