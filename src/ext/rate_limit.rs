//! Rate limit policy contracts for flows that need to consult provider budgets
//! before issuing token requests.

// self
use crate::{
	_prelude::*,
	auth::{ProviderId, ScopeSet, TenantId},
};

/// Boxed future returned by [`RateLimitPolicy::evaluate`].
pub type RateLimitFuture<'a, Error> =
	Pin<Box<dyn Future<Output = Result<RateLimitDecision, Error>> + 'a + Send>>;

/// Strategy that inspects tenant/provider budgets before flows hit upstream token endpoints.
pub trait RateLimitPolicy<Error>
where
	Self: Send + Sync,
{
	/// Evaluates whether the next call should be delayed.
	fn evaluate(&self, context: &RateLimitContext) -> RateLimitFuture<'_, Error>;
}

/// Context shared with a [`RateLimitPolicy`] before an outbound call is made.
#[derive(Clone, Debug)]
pub struct RateLimitContext {
	/// Tenant identifier for the call.
	pub tenant_id: TenantId,
	/// Provider identifier for the call.
	pub provider_id: ProviderId,
	/// Normalized scope set the broker is about to request.
	pub scope: ScopeSet,
	/// Logical operation (grant/flow) being attempted.
	pub operation: String,
	/// Timestamp the broker observed before invoking the policy.
	pub observed_at: OffsetDateTime,
}
impl RateLimitContext {
	/// Creates a new context for the given tenant/provider/scope/operation tuple.
	pub fn new(
		tenant_id: TenantId,
		provider_id: ProviderId,
		scope: ScopeSet,
		operation: impl Into<String>,
	) -> Self {
		Self {
			tenant_id,
			provider_id,
			scope,
			operation: operation.into(),
			observed_at: OffsetDateTime::now_utc(),
		}
	}

	/// Overrides the timestamp associated with the observation.
	pub fn with_observed_at(mut self, instant: OffsetDateTime) -> Self {
		self.observed_at = instant;

		self
	}
}

/// Result emitted by a [`RateLimitPolicy`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RateLimitDecision {
	/// The request may proceed immediately.
	Allow,
	/// The request should be delayed.
	Delay(RetryDirective),
}

/// Advises callers when to retry after a [`RateLimitDecision::Delay`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetryDirective {
	/// Instant when it is safe to retry.
	pub earliest_retry_at: OffsetDateTime,
	/// Suggested backoff duration.
	pub recommended_backoff: Duration,
	/// Optional descriptive string.
	pub reason: Option<String>,
}
impl RetryDirective {
	/// Creates a new directive with the provided timing metadata.
	pub fn new(earliest_retry_at: OffsetDateTime, recommended_backoff: Duration) -> Self {
		Self { earliest_retry_at, recommended_backoff, reason: None }
	}

	/// Adds a human-readable reason.
	pub fn with_reason(mut self, reason: impl Into<String>) -> Self {
		self.reason = Some(reason.into());

		self
	}
}
