//! Shared helpers for flow implementations (scope formatting, cached-request state, guards).

// self
use crate::{
	_prelude::*,
	auth::{PrincipalId, ScopeSet, TenantId, TokenRecord, TokenRecordBuilderError},
	error::ConfigError,
	flows::Broker,
	http::TokenHttpClient,
	oauth::TransportErrorMapper,
	store::StoreKey,
};

/// Shared request parameters for flows that evaluate cached records before
/// contacting the provider.
#[derive(Clone, Debug)]
pub struct CachedTokenRequest {
	/// Tenant identifier tied to the request.
	pub tenant: TenantId,
	/// Principal identifier tied to the request.
	pub principal: PrincipalId,
	/// Normalized scope set for the request.
	pub scope: ScopeSet,
	/// Forces cache bypass when true.
	pub force: bool,
	/// Jittered preemptive window used when refreshing early.
	pub preemptive_window: Duration,
}
impl CachedTokenRequest {
	const DEFAULT_PREEMPTIVE_WINDOW: Duration = Duration::seconds(60);

	/// Creates a new request for the provided tenant/principal/scope tuple.
	pub fn new(tenant: TenantId, principal: PrincipalId, scope: ScopeSet) -> Self {
		Self {
			tenant,
			principal,
			scope,
			force: false,
			preemptive_window: Self::DEFAULT_PREEMPTIVE_WINDOW,
		}
	}

	/// Forces the broker to bypass cache checks.
	pub fn force_refresh(mut self) -> Self {
		self.force = true;

		self
	}

	/// Overrides the force flag.
	pub fn with_force(mut self, force: bool) -> Self {
		self.force = force;

		self
	}

	/// Overrides the jittered preemptive window (defaults to 60 seconds).
	pub fn with_preemptive_window(mut self, window: Duration) -> Self {
		self.preemptive_window = if window.is_negative() { Duration::ZERO } else { window };

		self
	}

	/// Determines whether the cached record should be refreshed.
	pub fn should_refresh(&self, record: &TokenRecord, now: OffsetDateTime) -> bool {
		if self.force || record.is_revoked() || record.is_expired_at(now) {
			return true;
		}

		let effective_window = self.effective_preemptive_window();

		if effective_window.is_zero() {
			return false;
		}

		let remaining = record.expires_at - now;

		remaining <= effective_window
	}

	fn effective_preemptive_window(&self) -> Duration {
		self.preemptive_window.checked_sub(self.preemptive_jitter()).unwrap_or(Duration::ZERO)
	}

	fn preemptive_jitter(&self) -> Duration {
		let window_secs = self.preemptive_window.whole_seconds();

		if window_secs <= 1 {
			return Duration::ZERO;
		}

		let modulus = u64::try_from(window_secs).unwrap_or(u64::MAX);

		if modulus == 0 {
			return Duration::ZERO;
		}

		let jitter_secs = self.jitter_seed() % modulus;

		if jitter_secs == 0 {
			return Duration::ZERO;
		}

		let clamped = i64::try_from(jitter_secs).unwrap_or(i64::MAX);

		Duration::seconds(clamped)
	}

	fn jitter_seed(&self) -> u64 {
		let mut hasher = DefaultHasher::new();

		self.tenant.hash(&mut hasher);
		self.principal.hash(&mut hasher);
		self.scope.hash(&mut hasher);

		hasher.finish()
	}
}

/// Joins normalized scopes with the provider's delimiter when building requests.
pub(crate) fn format_scope(scope: &ScopeSet, delimiter: char) -> Option<String> {
	if scope.is_empty() {
		return None;
	}
	if delimiter == ' ' {
		return Some(scope.normalized());
	}

	let mut buf = String::new();

	for (idx, value) in scope.iter().enumerate() {
		if idx > 0 {
			buf.push(delimiter);
		}

		buf.push_str(value);
	}

	Some(buf)
}

/// Returns (and creates on demand) the singleflight guard for a store key.
pub(crate) fn flow_guard<C, M>(broker: &Broker<C, M>, key: &StoreKey) -> Arc<AsyncMutex<()>>
where
	C: ?Sized + TokenHttpClient,
	M: ?Sized + TransportErrorMapper<C::TransportError>,
{
	let mut guards = broker.flow_guards.lock();

	guards.entry(key.clone()).or_insert_with(|| Arc::new(AsyncMutex::new(()))).clone()
}

/// Normalizes token builder errors into broker errors.
pub(crate) fn map_token_builder_error(err: TokenRecordBuilderError) -> Error {
	ConfigError::from(err).into()
}

#[cfg(test)]
mod tests {
	// self
	use super::*;
	use crate::auth::ScopeSet;

	#[test]
	fn scope_formatting_handles_custom_delimiters() {
		let scope = ScopeSet::new(["email", "profile"]).expect("Failed to build test scope.");

		assert_eq!(format_scope(&scope, ' '), Some("email profile".into()));
		assert_eq!(format_scope(&scope, ','), Some("email,profile".into()));
	}
}
