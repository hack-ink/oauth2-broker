//! Client Credentials flow orchestration with caching + singleflight guards.
//!
//! The broker exposes [`Broker::client_credentials`] so callers can reuse cached
//! access tokens for service-to-service principals. Each request uses the same
//! tenant/principal/scope tuple used by other flows, evaluates a jittered
//! preemptive window, and only calls the provider when the cached record is
//! missing/expired/forced. A per-`StoreKey` singleflight guard ensures concurrent
//! callers piggy-back on the same in-flight refresh instead of stampeding the
//! token endpoint.

// self
use crate::{
	_prelude::*,
	auth::{TokenFamily, TokenRecord},
	error::ConfigError,
	flows::{
		Broker,
		common::{self, CachedTokenRequest},
	},
	http::TokenHttpClient,
	oauth::{BasicFacade, OAuth2Facade, TransportErrorMapper},
	obs::{self, FlowKind, FlowOutcome, FlowSpan},
	provider::{GrantType, ProviderStrategy},
	store::{BrokerStore, StoreKey},
};

impl<C, M> Broker<C, M>
where
	C: TokenHttpClient + ?Sized,
	M: TransportErrorMapper<C::TransportError> + ?Sized,
{
	/// Performs the `client_credentials` grant with caching + singleflight guards.
	pub async fn client_credentials(&self, request: CachedTokenRequest) -> Result<TokenRecord> {
		const KIND: FlowKind = FlowKind::ClientCredentials;

		let span = FlowSpan::new(KIND, "client_credentials");

		obs::record_flow_outcome(KIND, FlowOutcome::Attempt);

		let result = span
			.instrument(async move {
				self.ensure_client_credentials_supported()?;

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

				if let Some(current) =
					<dyn BrokerStore>::fetch(self.store.as_ref(), &family, &store_scope)
						.await
						.map_err(Error::from)?
						.filter(|record| !request.should_refresh(record, now))
				{
					return Ok(current);
				}

				let grant = GrantType::ClientCredentials;
				let mut form = {
					let mut map = BTreeMap::new();

					map.insert("grant_type".into(), grant.as_str().into());

					map
				};

				if let Some(scope_value) =
					common::format_scope(&requested_scope, self.descriptor.quirks.scope_delimiter)
				{
					form.insert("scope".into(), scope_value);
				}

				<dyn ProviderStrategy>::augment_token_request(
					self.strategy.as_ref(),
					grant,
					&mut form,
				);

				let extra_params: Vec<(String, String)> = form
					.into_iter()
					.filter(|(key, _)| key != "grant_type" && key != "scope")
					.collect();
				let scope_params = requested_scope.iter().collect::<Vec<_>>();
				let facade: BasicFacade<C, M> = BasicFacade::from_descriptor(
					&self.descriptor,
					&self.client_id,
					self.client_secret.as_deref(),
					None,
					self.http_client.clone(),
					self.transport_mapper.clone(),
				)?;
				let record = facade
					.exchange_client_credentials(
						self.strategy.as_ref(),
						family,
						scope_params.as_slice(),
						extra_params.as_slice(),
					)
					.await?;

				<dyn BrokerStore>::save(self.store.as_ref(), record.clone())
					.await
					.map_err(Error::from)?;

				Ok(record)
			})
			.await;

		match &result {
			Ok(_) => obs::record_flow_outcome(KIND, FlowOutcome::Success),
			Err(_) => obs::record_flow_outcome(KIND, FlowOutcome::Failure),
		}

		result
	}

	fn ensure_client_credentials_supported(&self) -> Result<()> {
		if self.descriptor.supports(GrantType::ClientCredentials) {
			Ok(())
		} else {
			Err(ConfigError::UnsupportedGrant {
				descriptor: self.descriptor.id.to_string(),
				grant: "client_credentials",
			}
			.into())
		}
	}
}
