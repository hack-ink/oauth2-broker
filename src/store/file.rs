//! Simple file-backed [`BrokerStore`] for lightweight deployments and bots.

// std
use std::{
	fs::{self, File},
	io::Write,
	path::{Path, PathBuf},
};
// self
use crate::{
	_prelude::*,
	auth::{ScopeSet, TokenFamily, TokenRecord, TokenSecret},
	store::{BrokerStore, CompareAndSwapOutcome, StoreError, StoreFuture, StoreKey},
};

/// Persists broker records to a JSON file after each mutation.
#[derive(Clone, Debug)]
pub struct FileStore {
	path: PathBuf,
	inner: Arc<RwLock<HashMap<StoreKey, TokenRecord>>>,
}
impl FileStore {
	/// Opens (or creates) a store at the provided path, eagerly loading existing data.
	pub fn open(path: impl Into<PathBuf>) -> Result<Self, StoreError> {
		let path = path.into();

		Self::ensure_parent_exists(&path)?;

		let snapshot = if path.exists() { Self::load_snapshot(&path)? } else { HashMap::new() };

		Ok(Self { path, inner: Arc::new(RwLock::new(snapshot)) })
	}

	fn load_snapshot(path: &Path) -> Result<HashMap<StoreKey, TokenRecord>, StoreError> {
		if !path.exists() {
			return Ok(HashMap::new());
		}

		let metadata = path.metadata().map_err(|e| StoreError::Backend {
			message: format!("Failed to inspect {}: {e}", path.display()),
		})?;

		if metadata.len() == 0 {
			return Ok(HashMap::new());
		}

		let bytes = fs::read(path).map_err(|e| StoreError::Backend {
			message: format!("Failed to read {}: {e}", path.display()),
		})?;

		let entries: Vec<(StoreKey, TokenRecord)> =
			serde_json::from_slice(&bytes).map_err(|e| StoreError::Serialization {
				message: format!("Failed to parse {}: {e}", path.display()),
			})?;

		Ok(entries.into_iter().collect())
	}

	fn ensure_parent_exists(path: &Path) -> Result<(), StoreError> {
		if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
			fs::create_dir_all(parent).map_err(|e| StoreError::Backend {
				message: format!("Failed to create store directory {}: {e}", parent.display()),
			})?;
		}
		Ok(())
	}

	fn persist_locked(&self, contents: &HashMap<StoreKey, TokenRecord>) -> Result<(), StoreError> {
		Self::ensure_parent_exists(&self.path)?;

		let snapshot: Vec<_> = contents.iter().collect();
		let serialized =
			serde_json::to_vec_pretty(&snapshot).map_err(|e| StoreError::Serialization {
				message: format!("Failed to serialize store snapshot: {e}"),
			})?;
		let mut tmp_path = self.path.clone();

		tmp_path.set_extension("tmp");

		{
			let mut file = File::create(&tmp_path).map_err(|e| StoreError::Backend {
				message: format!("Failed to create {}: {e}", tmp_path.display()),
			})?;

			file.write_all(&serialized).map_err(|e| StoreError::Backend {
				message: format!("Failed to write {}: {e}", tmp_path.display()),
			})?;
			file.sync_all().map_err(|e| StoreError::Backend {
				message: format!("Failed to sync {}: {e}", tmp_path.display()),
			})?;
		}

		fs::rename(&tmp_path, &self.path).map_err(|e| StoreError::Backend {
			message: format!("Failed to replace {}: {e}", self.path.display()),
		})
	}

	fn make_key(family: &TokenFamily, scope: &ScopeSet) -> StoreKey {
		StoreKey::new(family, scope)
	}

	fn refresh_matches(current: Option<&TokenSecret>, expected: Option<&str>) -> bool {
		match (current.map(TokenSecret::expose), expected) {
			(None, None) => true,
			(Some(cur), Some(exp)) => cur == exp,
			_ => false,
		}
	}
}
impl BrokerStore for FileStore {
	fn save(&self, record: TokenRecord) -> StoreFuture<'_, ()> {
		Box::pin(async move {
			let key = Self::make_key(&record.family, &record.scope);
			let mut guard = self.inner.write();

			guard.insert(key, record);
			self.persist_locked(&guard)?;

			Ok(())
		})
	}

	fn fetch<'a>(
		&'a self,
		family: &'a TokenFamily,
		scope: &'a ScopeSet,
	) -> StoreFuture<'a, Option<TokenRecord>> {
		Box::pin(async move {
			let key = Self::make_key(family, scope);

			Ok(self.inner.read().get(&key).cloned())
		})
	}

	fn compare_and_swap_refresh<'a>(
		&'a self,
		family: &'a TokenFamily,
		scope: &'a ScopeSet,
		expected_refresh: Option<&'a str>,
		replacement: TokenRecord,
	) -> StoreFuture<'a, CompareAndSwapOutcome> {
		Box::pin(async move {
			let key = Self::make_key(family, scope);
			let mut guard = self.inner.write();
			let outcome = match guard.get(&key) {
				Some(existing)
					if Self::refresh_matches(existing.refresh_token.as_ref(), expected_refresh) =>
					CompareAndSwapOutcome::Updated,
				Some(_) => CompareAndSwapOutcome::RefreshMismatch,
				None => CompareAndSwapOutcome::Missing,
			};

			if matches!(outcome, CompareAndSwapOutcome::Updated) {
				guard.insert(key, replacement);
				self.persist_locked(&guard)?;
			}

			Ok(outcome)
		})
	}

	fn revoke<'a>(
		&'a self,
		family: &'a TokenFamily,
		scope: &'a ScopeSet,
		instant: OffsetDateTime,
	) -> StoreFuture<'a, Option<TokenRecord>> {
		Box::pin(async move {
			let key = Self::make_key(family, scope);
			let mut guard = self.inner.write();
			let result = match guard.get_mut(&key) {
				Some(record) => {
					record.revoke(instant);

					let cloned = record.clone();

					self.persist_locked(&guard)?;

					Some(cloned)
				},
				None => None,
			};

			Ok(result)
		})
	}
}

#[cfg(test)]
mod tests {
	// std
	use std::{env, process};
	// crates.io
	use tokio::runtime::Runtime;
	// self
	use super::*;
	use crate::auth::{PrincipalId, TenantId};

	fn temp_path() -> PathBuf {
		let unique = format!(
			"oauth2_broker_file_store_{}_{}.json",
			process::id(),
			OffsetDateTime::now_utc().unix_timestamp_nanos(),
		);

		env::temp_dir().join(unique)
	}

	fn build_record() -> (TokenFamily, ScopeSet, TokenRecord) {
		let tenant = TenantId::new("tenant-demo").expect("Failed to build tenant fixture.");
		let principal =
			PrincipalId::new("principal-demo").expect("Failed to build principal fixture.");
		let scope = ScopeSet::new(["tweet.read"]).expect("Failed to build scope fixture.");
		let family = TokenFamily::new(tenant, principal);
		let record = TokenRecord::builder(family.clone(), scope.clone())
			.access_token("access-token")
			.expires_in(Duration::hours(1))
			.build()
			.expect("Failed to build file-store test record.");

		(family, scope, record)
	}

	#[test]
	fn save_and_reload_round_trip() {
		let path = temp_path();
		let store = FileStore::open(&path).expect("Failed to open file store snapshot.");
		let (family, scope, record) = build_record();
		let rt = Runtime::new().expect("Failed to build Tokio runtime for file store test.");

		rt.block_on(store.save(record.clone()))
			.expect("Failed to save fixture record to file store.");
		drop(store);

		let reopened = FileStore::open(&path).expect("Failed to reopen file store snapshot.");
		let fetched = rt
			.block_on(reopened.fetch(&family, &scope))
			.expect("Failed to fetch fixture record from file store.")
			.expect("File store lost record after reopen.");

		assert_eq!(fetched.access_token.expose(), record.access_token.expose());

		fs::remove_file(&path).unwrap_or_else(|e| {
			panic!("Failed to remove temporary file store snapshot {}: {e}", path.display())
		});
	}
}
