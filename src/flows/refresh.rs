//! Refresh token orchestration with singleflight guards, CAS rotation, and metrics.
//!
//! The broker exposes [`Broker::refresh_access_token`] so callers can request a fresh
//! access token for a tenant/principal/scope triple without worrying about
//! concurrent rotations. Each request acquires a per-`StoreKey` guard, evaluates
//! a jittered preemptive window, and either reuses the cached record or performs a
//! `grant_type=refresh_token` call. Successful refreshes rotate secrets via
//! `BrokerStore::compare_and_swap_refresh`, while invalid_grant/revoked responses
//! revoke the cached record.

mod metrics;

pub use metrics::RefreshMetrics;

// self
use crate::{
	_prelude::*,
	auth::{TokenFamily, TokenRecord},
	error::ConfigError,
	flows::{Broker, CachedTokenRequest, common},
	http::TokenHttpClient,
	oauth::{BasicFacade, OAuth2Facade, TransportErrorMapper},
	obs::{self, FlowKind, FlowOutcome, FlowSpan},
	provider::GrantType,
	store::{BrokerStore, CompareAndSwapOutcome, StoreKey},
};

impl<C, M> Broker<C, M>
where
	C: ?Sized + TokenHttpClient,
	M: ?Sized + TransportErrorMapper<C::TransportError>,
{
	/// Refreshes the cached token family, performing CAS rotation + singleflight guards.
	pub async fn refresh_access_token(&self, request: CachedTokenRequest) -> Result<TokenRecord> {
		const KIND: FlowKind = FlowKind::Refresh;

		let span = FlowSpan::new(KIND, "refresh_access_token");

		obs::record_flow_outcome(KIND, FlowOutcome::Attempt);

		let result = span
			.instrument(async move {
				self.ensure_refresh_supported()?;
				self.refresh_metrics.record_attempt();

				let tenant = request.tenant.clone();
				let principal = request.principal.clone();
				let store_scope = request.scope.clone();
				let requested_scope = store_scope.clone();
				let mut family = TokenFamily::new(tenant, principal);

				family.provider = Some(self.descriptor.id.clone());

				let key = StoreKey::new(&family, &store_scope);
				let guard = common::flow_guard(self, &key);
				let _singleflight = guard.lock().await;
				let now = OffsetDateTime::now_utc();
				let current = <dyn BrokerStore>::fetch(self.store.as_ref(), &family, &store_scope)
					.await
					.map_err(|err| {
						self.refresh_metrics.record_failure();
						Error::from(err)
					})?
					.ok_or_else(|| {
						self.refresh_metrics.record_failure();

						Error::InvalidGrant {
							reason: "No cached token record is available for refresh operations."
								.into(),
						}
					})?;

				if !request.should_refresh(&current, now) {
					self.refresh_metrics.record_success();

					return Ok(current);
				}

				let expected_refresh = current
					.refresh_token
					.as_ref()
					.map(|secret| secret.expose().to_string())
					.ok_or_else(|| {
						self.refresh_metrics.record_failure();

						Error::from(ConfigError::MissingRefreshToken)
					})?;
				let facade = <BasicFacade<C, M>>::from_descriptor(
					&self.descriptor,
					&self.client_id,
					self.client_secret.as_deref(),
					None,
					self.http_client.clone(),
					self.transport_mapper.clone(),
				)
				.inspect_err(|_| {
					self.refresh_metrics.record_failure();
				})?;
				let (facade_record, new_refresh) = match facade
					.refresh_token(
						self.strategy.as_ref(),
						family.clone(),
						&expected_refresh,
						&requested_scope,
					)
					.await
				{
					Ok(result) => result,
					Err(err) => {
						if matches!(err, Error::InvalidGrant { .. } | Error::Revoked) {
							let _ = <dyn BrokerStore>::revoke(
								self.store.as_ref(),
								&family,
								&store_scope,
								now,
							)
							.await;
						}

						self.refresh_metrics.record_failure();

						return Err(err);
					},
				};
				let updated = if new_refresh.is_some() {
					facade_record
				} else {
					let mut builder = TokenRecord::builder(
						facade_record.family.clone(),
						facade_record.scope.clone(),
					)
					.access_token(facade_record.access_token.expose())
					.issued_at(facade_record.issued_at)
					.expires_at(facade_record.expires_at);

					builder = builder.refresh_token(expected_refresh.clone());

					builder.build().map_err(|err| {
						self.refresh_metrics.record_failure();

						common::map_token_builder_error(err)
					})?
				};
				let outcome = <dyn BrokerStore>::compare_and_swap_refresh(
					self.store.as_ref(),
					&family,
					&store_scope,
					Some(expected_refresh.as_str()),
					updated.clone(),
				)
				.await
				.map_err(|err| {
					self.refresh_metrics.record_failure();

					Error::from(err)
				})?;
				let result = match outcome {
					CompareAndSwapOutcome::Updated => updated,
					CompareAndSwapOutcome::Missing => {
						<dyn BrokerStore>::save(self.store.as_ref(), updated.clone())
							.await
							.map_err(|err| {
								self.refresh_metrics.record_failure();
								Error::from(err)
							})?;

						updated
					},
					CompareAndSwapOutcome::RefreshMismatch => {
						match <dyn BrokerStore>::fetch(self.store.as_ref(), &family, &store_scope)
							.await
							.map_err(|err| {
								self.refresh_metrics.record_failure();
								Error::from(err)
							})? {
							Some(existing) => existing,
							None => {
								<dyn BrokerStore>::save(self.store.as_ref(), updated.clone())
									.await
									.map_err(|err| {
										self.refresh_metrics.record_failure();
										Error::from(err)
									})?;

								updated
							},
						}
					},
				};

				self.refresh_metrics.record_success();
				Ok(result)
			})
			.await;

		match &result {
			Ok(_) => obs::record_flow_outcome(KIND, FlowOutcome::Success),
			Err(_) => obs::record_flow_outcome(KIND, FlowOutcome::Failure),
		}

		result
	}

	fn ensure_refresh_supported(&self) -> Result<()> {
		if self.descriptor.supports(GrantType::RefreshToken) {
			Ok(())
		} else {
			Err(ConfigError::UnsupportedGrant {
				descriptor: self.descriptor.id.to_string(),
				grant: "refresh_token",
			}
			.into())
		}
	}
}
