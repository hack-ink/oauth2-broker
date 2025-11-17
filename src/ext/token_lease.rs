//! Token leasing contracts that let callers borrow access tokens for short
//! windows while the broker controls refresh lifetimes.

// self
use crate::{
	_prelude::*,
	auth::{ScopeSet, TokenFamily},
};

/// Boxed future returned by [`TokenLeaseExt::lease`].
pub type TokenLeaseFuture<'a, Lease, Error> =
	Pin<Box<dyn Future<Output = Result<TokenLeaseState<Lease>, Error>> + 'a + Send>>;

/// Contract for cache providers that want to loan out access tokens while the broker governs
/// refresh lifetimes.
pub trait TokenLeaseExt<Lease, Error>: Send + Sync {
	/// Attempts to borrow a token for the provided context.
	fn lease(&self, context: TokenLeaseContext) -> TokenLeaseFuture<'_, Lease, Error>;
}

/// Metadata describing what kind of lease the caller is requesting.
#[derive(Clone, Debug)]
pub struct TokenLeaseContext {
	/// Token family tied to the lease.
	pub family: TokenFamily,
	/// Scope set tied to the lease.
	pub scope: ScopeSet,
	/// Instant that should be treated as "now" for freshness checks.
	pub requested_at: OffsetDateTime,
	/// Minimum TTL the caller wants to guarantee.
	pub minimum_ttl: Duration,
	/// Optional annotation that can flow into logs/metrics.
	pub reason: Option<String>,
}
impl TokenLeaseContext {
	/// Creates a new context for the provided token family + scope set.
	pub fn new(family: TokenFamily, scope: ScopeSet) -> Self {
		Self {
			family,
			scope,
			requested_at: OffsetDateTime::now_utc(),
			minimum_ttl: Duration::ZERO,
			reason: None,
		}
	}

	/// Overrides the instant used for freshness calculations.
	pub fn with_requested_at(mut self, instant: OffsetDateTime) -> Self {
		self.requested_at = instant;

		self
	}

	/// Ensures the lease is only granted if the token will remain valid for at
	/// least the provided TTL.
	pub fn with_minimum_ttl(mut self, ttl: Duration) -> Self {
		self.minimum_ttl = ttl;

		self
	}

	/// Adds an optional human-readable reason for observability.
	pub fn with_reason(mut self, reason: impl Into<String>) -> Self {
		self.reason = Some(reason.into());

		self
	}
}

/// Result of attempting to lease a token.
pub enum TokenLeaseState<Lease> {
	/// A guard was produced. Dropping the guard should release the lease.
	Granted {
		/// User-defined guard that owns the lease lifetime.
		lease: Lease,
		/// Expiry instant for the leased token record.
		expires_at: OffsetDateTime,
	},
	/// A lease will be available later; callers should retry after the delay.
	Pending {
		/// Duration callers should wait before retrying.
		retry_in: Duration,
	},
	/// No usable token exists; flows should refresh or mint a new one.
	NeedsRefresh,
}
impl<Lease> Debug for TokenLeaseState<Lease> {
	fn fmt(&self, f: &mut Formatter) -> FmtResult {
		match self {
			Self::Granted { expires_at, .. } =>
				f.debug_struct("TokenLeaseState::Granted").field("expires_at", expires_at).finish(),
			Self::Pending { retry_in } =>
				f.debug_struct("TokenLeaseState::Pending").field("retry_in", retry_in).finish(),
			Self::NeedsRefresh => f.debug_struct("TokenLeaseState::NeedsRefresh").finish(),
		}
	}
}
