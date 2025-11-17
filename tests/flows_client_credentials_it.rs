// crates.io
use httpmock::prelude::*;
// self
use oauth2_broker::{
	_preludet::*,
	auth::{PrincipalId, ProviderId, ScopeSet, TenantId, TokenRecord},
	flows::CachedTokenRequest,
	provider::{ClientAuthMethod, GrantType, ProviderDescriptor},
	store::BrokerStore,
};

const CLIENT_ID: &str = "client-credentials";
const CLIENT_SECRET: &str = "secret-credentials";

fn build_descriptor(server: &MockServer) -> ProviderDescriptor {
	let provider_id = ProviderId::new("mock-client-credentials")
		.expect("Provider identifier should be valid for client credentials tests.");

	ProviderDescriptor::builder(provider_id)
		.authorization_endpoint(
			Url::parse(&server.url("/authorize"))
				.expect("Mock authorization endpoint should parse successfully."),
		)
		.token_endpoint(
			Url::parse(&server.url("/token"))
				.expect("Mock token endpoint should parse successfully."),
		)
		.support_grants([GrantType::ClientCredentials])
		.preferred_client_auth_method(ClientAuthMethod::ClientSecretPost)
		.build()
		.expect("Provider descriptor should build successfully.")
}

#[tokio::test]
async fn client_credentials_caches_token_after_success() {
	let server = MockServer::start_async().await;
	let descriptor = build_descriptor(&server);
	let (broker, store) = build_reqwest_test_broker(descriptor.clone(), CLIENT_ID, CLIENT_SECRET);
	let tenant = TenantId::new("tenant-cc-cache")
		.expect("Tenant identifier should be valid for client credentials cache test.");
	let principal = PrincipalId::new("principal-cc-cache")
		.expect("Principal identifier should be valid for client credentials cache test.");
	let scope = ScopeSet::new(["api.read", "api.write"])
		.expect("Scope set should be valid for client credentials cache test.");
	let mock = server
		.mock_async(|when, then| {
			when.method(POST).path("/token");
			then.status(200).header("content-type", "application/json").body(
				"{\"access_token\":\"cached-token\",\"token_type\":\"bearer\",\"expires_in\":1800}",
			);
		})
		.await;
	let request = CachedTokenRequest::new(tenant.clone(), principal.clone(), scope.clone());
	let first = broker
		.client_credentials(request.clone())
		.await
		.expect("Initial client_credentials request should succeed.");
	let second = broker
		.client_credentials(request)
		.await
		.expect("Cached client_credentials request should succeed.");

	assert_eq!(first.access_token.expose(), "cached-token");
	assert_eq!(second.access_token.expose(), "cached-token");

	mock.assert_calls_async(1).await;

	let stored = store
		.fetch(&first.family, &first.scope)
		.await
		.expect("Token store fetch should succeed.")
		.expect("Stored record should remain present.");

	assert_eq!(stored.access_token.expose(), "cached-token");
}

#[tokio::test]
async fn client_credentials_singleflight_requests_once() {
	let server = MockServer::start_async().await;
	let descriptor = build_descriptor(&server);
	let (broker, _store) = build_reqwest_test_broker(descriptor, CLIENT_ID, CLIENT_SECRET);
	let tenant = TenantId::new("tenant-cc-guard")
		.expect("Tenant identifier should be valid for singleflight test.");
	let principal = PrincipalId::new("principal-cc-guard")
		.expect("Principal identifier should be valid for singleflight test.");
	let scope =
		ScopeSet::new(["notifications"]).expect("Scope set should be valid for singleflight test.");
	let mock = server
		.mock_async(|when, then| {
			when.method(POST).path("/token");
			then.status(200).header("content-type", "application/json").body(
				"{\"access_token\":\"guard-token\",\"token_type\":\"bearer\",\"expires_in\":900}",
			);
		})
		.await;
	let request = CachedTokenRequest::new(tenant, principal, scope);
	let (first, second): (Result<TokenRecord>, Result<TokenRecord>) = tokio::join!(
		broker.client_credentials(request.clone()),
		broker.client_credentials(request),
	);
	let first = first.expect("First concurrent call should succeed.");
	let second = second.expect("Second concurrent call should succeed.");

	assert_eq!(first.access_token.expose(), "guard-token");
	assert_eq!(second.access_token.expose(), "guard-token");

	mock.assert_calls_async(1).await;
}

#[tokio::test]
async fn client_credentials_maps_invalid_grant() {
	let server = MockServer::start_async().await;
	let descriptor = build_descriptor(&server);
	let (broker, _store) = build_reqwest_test_broker(descriptor, CLIENT_ID, CLIENT_SECRET);
	let tenant = TenantId::new("tenant-cc-invalid")
		.expect("Tenant identifier should be valid for invalid grant test.");
	let principal = PrincipalId::new("principal-cc-invalid")
		.expect("Principal identifier should be valid for invalid grant test.");
	let scope =
		ScopeSet::new(["api.fail"]).expect("Scope set should be valid for invalid grant test.");
	let mock = server
		.mock_async(|when, then| {
			when.method(POST).path("/token");
			then.status(400)
				.header("content-type", "application/json")
				.body("{\"error\":\"invalid_grant\"}");
		})
		.await;
	let err = broker
		.client_credentials(CachedTokenRequest::new(tenant, principal, scope))
		.await
		.expect_err("Invalid grant errors should surface to the caller.");

	assert!(matches!(err, Error::InvalidGrant { .. }));

	mock.assert_async().await;
}
