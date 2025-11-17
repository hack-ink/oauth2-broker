//! Demonstrates using the broker’s client-credentials flow with the default reqwest transport
//! and in-memory token store to reuse cached service tokens.

// std
use std::sync::Arc;
// crates.io
use color_eyre::Result;
use httpmock::prelude::*;
use url::Url;
// self
use oauth2_broker::{
	auth::{PrincipalId, ProviderId, ScopeSet, TenantId},
	flows::{Broker, CachedTokenRequest},
	http::ReqwestHttpClient,
	oauth::ReqwestTransportErrorMapper,
	provider::{DefaultProviderStrategy, GrantType, ProviderDescriptor, ProviderStrategy},
	reqwest::Client,
	store::{BrokerStore, MemoryStore},
};

#[tokio::main]
async fn main() -> Result<()> {
	color_eyre::install()?;

	let store: Arc<dyn BrokerStore> = Arc::new(MemoryStore::default());
	let strategy: Arc<dyn ProviderStrategy> = Arc::new(DefaultProviderStrategy);
	let server = MockServer::start_async().await;
	let token_mock = server
		.mock_async(|when, then| {
			when.method(POST).path("/token");
			then.status(200).header("content-type", "application/json").body(
				"{\"access_token\":\"demo-access\",\"token_type\":\"bearer\",\"expires_in\":900}",
			);
		})
		.await;
	let descriptor = ProviderDescriptor::builder(ProviderId::new("demo-provider")?)
		.authorization_endpoint(Url::parse(&server.url("/authorize"))?)
		.token_endpoint(Url::parse(&server.url("/token"))?)
		.support_grant(GrantType::ClientCredentials)
		.build()?;
	let http_client = ReqwestHttpClient::with_client(
		Client::builder()
			.danger_accept_invalid_certs(true)
			.danger_accept_invalid_hostnames(true)
			.build()?,
	);
	let mapper = <Arc<ReqwestTransportErrorMapper>>::new(ReqwestTransportErrorMapper);
	let broker = <Broker<ReqwestHttpClient, ReqwestTransportErrorMapper>>::with_http_client(
		store,
		descriptor,
		strategy,
		"demo-client",
		http_client,
		mapper,
	)
	.with_client_secret("super-secret");
	let request = CachedTokenRequest::new(
		TenantId::new("tenant-acme")?,
		PrincipalId::new("service-router")?,
		ScopeSet::new(["email.read", "profile.read"])?,
	);
	let record = broker.client_credentials(request).await?;

	println!("Reusable access token: {}.", record.access_token.expose());

	token_mock.assert_async().await;

	Ok(())
}
