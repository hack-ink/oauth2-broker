//! Optional observability helpers for broker flows.
//!
//! # Feature Flags
//!
//! - Enable `tracing` to emit structured spans named `oauth2_broker.flow` with the `flow` (grant)
//!   and `stage` (call site) fields.
//! - Enable `metrics` to increment the `oauth2_broker_flow_total` counter for every
//!   attempt/success/failure, labeled by `flow` + `outcome`.

mod metrics;
mod tracing;

pub use metrics::*;
pub use tracing::*;

// self
use crate::_prelude::*;

/// OAuth flow kinds observed by the broker.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FlowKind {
	/// Authorization Code + PKCE grant helpers.
	AuthorizationCode,
	/// Refresh token flow.
	Refresh,
	/// Client Credentials flow.
	ClientCredentials,
}
impl FlowKind {
	/// Returns a stable label suitable for span or metric fields.
	pub const fn as_str(self) -> &'static str {
		match self {
			FlowKind::AuthorizationCode => "authorization_code",
			FlowKind::Refresh => "refresh",
			FlowKind::ClientCredentials => "client_credentials",
		}
	}
}
impl Display for FlowKind {
	fn fmt(&self, f: &mut Formatter) -> FmtResult {
		f.write_str(self.as_str())
	}
}

/// Outcome labels recorded for each attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FlowOutcome {
	/// Entry to a broker helper.
	Attempt,
	/// Successful completion.
	Success,
	/// Failure propagated back to the caller.
	Failure,
}
impl FlowOutcome {
	/// Returns a stable label suitable for span or metric fields.
	pub const fn as_str(self) -> &'static str {
		match self {
			FlowOutcome::Attempt => "attempt",
			FlowOutcome::Success => "success",
			FlowOutcome::Failure => "failure",
		}
	}
}
impl Display for FlowOutcome {
	fn fmt(&self, f: &mut Formatter) -> FmtResult {
		f.write_str(self.as_str())
	}
}
