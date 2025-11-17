//! Immutable token record structs, lifecycle helpers, and builders.

// self
use crate::{
	_prelude::*,
	auth::{
		ScopeSet,
		token::{family::TokenFamily, secret::TokenSecret},
	},
};

/// Current lifecycle status for a token record.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TokenStatus {
	/// Token is not yet valid because the issued-at instant is in the future.
	Pending,
	/// Token is currently valid.
	Active,
	/// Token exceeded its expiry instant.
	Expired,
	/// Token has been revoked locally or by the provider.
	Revoked,
}

/// Errors produced by [`TokenRecordBuilder`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ThisError)]
pub enum TokenRecordBuilderError {
	/// Issued when no access token value was provided.
	#[error("Access token is required.")]
	MissingAccessToken,
	/// Issued when no expiry (absolute or relative) was configured.
	#[error("Expiry must be supplied via expires_at or expires_in.")]
	MissingExpiry,
}

/// Immutable record describing issued OAuth tokens.
#[derive(Serialize, Deserialize, Clone)]
pub struct TokenRecord {
	/// Logical token grouping (tenant/principal/provider).
	pub family: TokenFamily,
	/// Normalized scopes granted to this record.
	pub scope: ScopeSet,
	/// Access token secret; callers must avoid logging it.
	pub access_token: TokenSecret,
	/// Refresh token secret, if the provider issued one.
	pub refresh_token: Option<TokenSecret>,
	/// Issued-at instant recorded from the provider response.
	pub issued_at: OffsetDateTime,
	/// Expiry instant derived from issued_at plus expires_in or absolute expiry.
	pub expires_at: OffsetDateTime,
	/// Revocation instant if the record has been revoked.
	pub revoked_at: Option<OffsetDateTime>,
}
impl TokenRecord {
	/// Returns a builder for constructing rotation-friendly records.
	pub fn builder(family: TokenFamily, scope: ScopeSet) -> TokenRecordBuilder {
		TokenRecordBuilder::new(family, scope)
	}

	/// Computes the lifecycle status at a given instant.
	pub fn status_at(&self, instant: OffsetDateTime) -> TokenStatus {
		if self.revoked_at.is_some() {
			return TokenStatus::Revoked;
		}
		if instant < self.issued_at {
			return TokenStatus::Pending;
		}
		if instant >= self.expires_at {
			return TokenStatus::Expired;
		}

		TokenStatus::Active
	}

	/// Convenience helper that checks the status using the current UTC instant.
	pub fn status(&self) -> TokenStatus {
		self.status_at(OffsetDateTime::now_utc())
	}

	/// Returns `true` if the record is considered pending at the provided instant.
	pub fn is_pending_at(&self, instant: OffsetDateTime) -> bool {
		matches!(self.status_at(instant), TokenStatus::Pending)
	}

	/// Returns `true` if the record is currently pending (issued_at in the future).
	pub fn is_pending(&self) -> bool {
		matches!(self.status(), TokenStatus::Pending)
	}

	/// Returns `true` if the record is currently active (not pending/expired/revoked).
	pub fn is_active(&self) -> bool {
		matches!(self.status(), TokenStatus::Active)
	}

	/// Returns `true` if the record has expired at the provided instant.
	pub fn is_expired_at(&self, instant: OffsetDateTime) -> bool {
		matches!(self.status_at(instant), TokenStatus::Expired)
	}

	/// Returns `true` if the record is expired relative to the current clock.
	pub fn is_expired(&self) -> bool {
		matches!(self.status(), TokenStatus::Expired)
	}

	/// Returns `true` if the record has been revoked.
	pub fn is_revoked(&self) -> bool {
		self.revoked_at.is_some()
	}

	/// Marks the record as revoked.
	pub fn revoke(&mut self, instant: OffsetDateTime) {
		self.revoked_at = Some(instant);
	}
}
impl Debug for TokenRecord {
	fn fmt(&self, f: &mut Formatter) -> FmtResult {
		f.debug_struct("TokenRecord")
			.field("family", &self.family)
			.field("scope", &self.scope)
			.field("access_token", &"<redacted>")
			.field("refresh_token", &self.refresh_token.as_ref().map(|_| "<redacted>"))
			.field("issued_at", &self.issued_at)
			.field("expires_at", &self.expires_at)
			.field("revoked_at", &self.revoked_at)
			.finish()
	}
}

/// Builder for [`TokenRecord`].
#[derive(Clone, Debug)]
pub struct TokenRecordBuilder {
	family: TokenFamily,
	scope: ScopeSet,
	access_token: Option<TokenSecret>,
	refresh_token: Option<TokenSecret>,
	issued_at: Option<OffsetDateTime>,
	expires_at: Option<OffsetDateTime>,
	expires_in: Option<Duration>,
}
impl TokenRecordBuilder {
	fn new(family: TokenFamily, scope: ScopeSet) -> Self {
		Self {
			family,
			scope,
			access_token: None,
			refresh_token: None,
			issued_at: None,
			expires_at: None,
			expires_in: None,
		}
	}

	/// Sets the issued-at instant.
	pub fn issued_at(mut self, instant: OffsetDateTime) -> Self {
		self.issued_at = Some(instant);

		self
	}

	/// Convenience helper that stamps `issued_at` with the current clock.
	pub fn issued_now(self) -> Self {
		self.issued_at(OffsetDateTime::now_utc())
	}

	/// Sets an absolute expiry instant.
	pub fn expires_at(mut self, instant: OffsetDateTime) -> Self {
		self.expires_at = Some(instant);

		self
	}

	/// Sets a relative expiry duration from the issued instant.
	pub fn expires_in(mut self, duration: Duration) -> Self {
		self.expires_in = Some(duration);

		self
	}

	/// Provides the access token value.
	pub fn access_token(mut self, token: impl Into<String>) -> Self {
		self.access_token = Some(TokenSecret::new(token));

		self
	}

	/// Provides the refresh token value.
	pub fn refresh_token(mut self, token: impl Into<String>) -> Self {
		self.refresh_token = Some(TokenSecret::new(token));

		self
	}

	/// Consumes the builder and produces a [`TokenRecord`].
	pub fn build(self) -> Result<TokenRecord, TokenRecordBuilderError> {
		let access_token = self.access_token.ok_or(TokenRecordBuilderError::MissingAccessToken)?;
		let issued_at = self.issued_at.unwrap_or_else(OffsetDateTime::now_utc);
		let expires_at = match (self.expires_at, self.expires_in) {
			(Some(instant), _) => instant,
			(None, Some(delta)) => issued_at + delta,
			(None, None) => return Err(TokenRecordBuilderError::MissingExpiry),
		};

		Ok(TokenRecord {
			family: self.family,
			scope: self.scope,
			access_token,
			refresh_token: self.refresh_token,
			issued_at,
			expires_at,
			revoked_at: None,
		})
	}
}

#[cfg(test)]
mod tests {
	// crates.io
	use time::macros;
	// self
	use super::*;
	use crate::auth::{PrincipalId, TenantId};

	#[test]
	fn status_transitions_cover_all_states() {
		let tenant = TenantId::new("t-1").expect("Tenant fixture should be valid.");
		let principal = PrincipalId::new("p-1").expect("Principal fixture should be valid.");
		let family = TokenFamily::new(tenant, principal);
		let scope = ScopeSet::new(["email", "profile"])
			.expect("Scope fixture should be valid for token record tests.");
		let issued = macros::datetime!(2025-01-01 00:00 UTC);
		let expires = macros::datetime!(2025-01-01 01:00 UTC);
		let mut record = TokenRecord::builder(family.clone(), scope)
			.access_token("access")
			.refresh_token("refresh")
			.issued_at(issued)
			.expires_at(expires)
			.build()
			.expect("Token record builder should succeed for status transitions.");

		assert_eq!(record.status_at(macros::datetime!(2024-12-31 23:59 UTC)), TokenStatus::Pending);
		assert_eq!(record.status_at(macros::datetime!(2025-01-01 00:30 UTC)), TokenStatus::Active);
		assert_eq!(record.status_at(macros::datetime!(2025-01-01 01:00 UTC)), TokenStatus::Expired);

		record.revoke(macros::datetime!(2025-01-01 00:10 UTC));

		assert_eq!(record.status_at(macros::datetime!(2025-01-01 00:30 UTC)), TokenStatus::Revoked);
	}

	#[test]
	fn builder_handles_relative_expiry() {
		let tenant = TenantId::new("tenant").expect("Tenant fixture should be valid.");
		let principal = PrincipalId::new("principal").expect("Principal fixture should be valid.");
		let family = TokenFamily::new(tenant, principal);
		let scope = ScopeSet::new(["email"])
			.expect("Scope fixture should be valid for relative expiry test.");
		let record = TokenRecord::builder(family, scope)
			.access_token("secret")
			.issued_at(macros::datetime!(2025-01-01 00:00 UTC))
			.expires_in(Duration::minutes(30))
			.build()
			.expect("Token record builder should support relative expiry calculations.");

		assert_eq!(record.expires_at, macros::datetime!(2025-01-01 00:30 UTC));
	}

	#[test]
	fn helper_methods_match_statuses() {
		let tenant = TenantId::new("t").expect("Tenant fixture should be valid.");
		let principal = PrincipalId::new("p").expect("Principal fixture should be valid.");
		let scope = ScopeSet::new(["email"])
			.expect("Scope fixture should be valid for helper method coverage.");
		let now = OffsetDateTime::now_utc();
		let pending = TokenRecord::builder(
			TokenFamily::new(tenant.clone(), principal.clone()),
			scope.clone(),
		)
		.access_token("pending")
		.issued_at(now + Duration::minutes(5))
		.expires_at(now + Duration::hours(1))
		.build()
		.expect("Pending record builder should succeed.");

		assert!(pending.is_pending());
		assert!(pending.is_pending_at(now));
		assert!(!pending.is_active());

		let mut active = TokenRecord::builder(
			TokenFamily::new(tenant.clone(), principal.clone()),
			scope.clone(),
		)
		.access_token("active")
		.issued_at(now - Duration::minutes(1))
		.expires_at(now + Duration::minutes(1))
		.build()
		.expect("Active record builder should succeed.");

		assert!(active.is_active());
		assert!(!active.is_revoked());

		active.revoke(now);

		assert!(active.is_revoked());

		let expired = TokenRecord::builder(TokenFamily::new(tenant, principal), scope)
			.access_token("expired")
			.issued_at(now - Duration::hours(2))
			.expires_at(now - Duration::minutes(1))
			.build()
			.expect("Expired record builder should succeed.");

		assert!(expired.is_expired());
		assert!(expired.is_expired_at(now));
	}
}
