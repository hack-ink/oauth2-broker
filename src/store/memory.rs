//! Thread-safe in-memory [`BrokerStore`] implementation for local development and tests.

// self
use crate::{
	_prelude::*,
	auth::{ScopeSet, TokenFamily, TokenRecord, token::secret::TokenSecret},
	store::{BrokerStore, CompareAndSwapOutcome, StoreError, StoreFuture, StoreKey},
};

type StoreMap = Arc<RwLock<HashMap<StoreKey, TokenRecord>>>;

/// Thread-safe storage backend that keeps records in-process for tests and demos.
#[derive(Clone, Debug, Default)]
pub struct MemoryStore(StoreMap);
impl MemoryStore {
	fn save_now(map: StoreMap, record: TokenRecord) -> Result<(), StoreError> {
		let key = StoreKey::new(&record.family, &record.scope);

		map.write().insert(key, record);

		Ok(())
	}

	fn fetch_now(map: StoreMap, family: TokenFamily, scope: ScopeSet) -> Option<TokenRecord> {
		let key = StoreKey::new(&family, &scope);

		map.read().get(&key).cloned()
	}

	fn cas_now(
		map: StoreMap,
		family: TokenFamily,
		scope: ScopeSet,
		expected_refresh: Option<&str>,
		replacement: TokenRecord,
	) -> CompareAndSwapOutcome {
		let key = StoreKey::new(&family, &scope);
		let mut guard = map.write();
		let outcome = match guard.get(&key) {
			Some(existing)
				if Self::refresh_matches(existing.refresh_token.as_ref(), expected_refresh) =>
				CompareAndSwapOutcome::Updated,
			Some(_) => CompareAndSwapOutcome::RefreshMismatch,
			None => CompareAndSwapOutcome::Missing,
		};

		if matches!(outcome, CompareAndSwapOutcome::Updated) {
			guard.insert(key, replacement);
		}

		outcome
	}

	fn refresh_matches(current: Option<&TokenSecret>, expected: Option<&str>) -> bool {
		match (current.map(TokenSecret::expose), expected) {
			(None, None) => true,
			(Some(cur), Some(exp)) => cur == exp,
			_ => false,
		}
	}

	fn revoke_now(
		map: StoreMap,
		family: TokenFamily,
		scope: ScopeSet,
		instant: OffsetDateTime,
	) -> Option<TokenRecord> {
		let key = StoreKey::new(&family, &scope);
		let mut guard = map.write();

		match guard.get_mut(&key) {
			Some(record) => {
				record.revoke(instant);

				Some(record.clone())
			},
			None => None,
		}
	}
}
impl BrokerStore for MemoryStore {
	fn save(&self, record: TokenRecord) -> StoreFuture<'_, ()> {
		let map = self.0.clone();

		Box::pin(async move { Self::save_now(map, record) })
	}

	fn fetch<'a>(
		&'a self,
		family: &'a TokenFamily,
		scope: &'a ScopeSet,
	) -> StoreFuture<'a, Option<TokenRecord>> {
		let map = self.0.clone();
		let family = family.to_owned();
		let scope = scope.to_owned();

		Box::pin(async move { Ok(Self::fetch_now(map, family, scope)) })
	}

	fn compare_and_swap_refresh<'a>(
		&'a self,
		family: &'a TokenFamily,
		scope: &'a ScopeSet,
		expected_refresh: Option<&'a str>,
		replacement: TokenRecord,
	) -> StoreFuture<'a, CompareAndSwapOutcome> {
		let map = self.0.clone();
		let family = family.to_owned();
		let scope = scope.to_owned();

		Box::pin(
			async move { Ok(Self::cas_now(map, family, scope, expected_refresh, replacement)) },
		)
	}

	fn revoke<'a>(
		&'a self,
		family: &'a TokenFamily,
		scope: &'a ScopeSet,
		instant: OffsetDateTime,
	) -> StoreFuture<'a, Option<TokenRecord>> {
		let map = self.0.clone();
		let family = family.to_owned();
		let scope = scope.to_owned();

		Box::pin(async move { Ok(Self::revoke_now(map, family, scope, instant)) })
	}
}
