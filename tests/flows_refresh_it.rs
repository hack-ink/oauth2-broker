#![cfg(feature = "reqwest")]

// crates.io
use httpmock::prelude::*;
// self
use oauth2_broker::{
	_preludet::*,
	auth::{PrincipalId, ProviderId, ScopeSet, TenantId, TokenFamily, TokenRecord},
	flows::CachedTokenRequest,
	provider::{ClientAuthMethod, GrantType, ProviderDescriptor},
	store::{BrokerStore, MemoryStore},
};

const CLIENT_ID: &str = "client-refresh";
const CLIENT_SECRET: &str = "secret-refresh";

#[allow(clippy::too_many_arguments)]
async fn seed_record(
	store: &MemoryStore,
	descriptor: &ProviderDescriptor,
	tenant: TenantId,
	principal: PrincipalId,
	scope: ScopeSet,
	access: &str,
	refresh: &str,
	expires_in: Duration,
) {
	let mut family = TokenFamily::new(tenant, principal);

	family.provider = Some(descriptor.id.clone());

	let issued = OffsetDateTime::now_utc() - Duration::minutes(5);
	let record = TokenRecord::builder(family, scope)
		.access_token(access.to_string())
		.refresh_token(refresh.to_string())
		.issued_at(issued)
		.expires_at(issued + expires_in)
		.build()
		.expect("Token record fixture should build successfully.");

	store.save(record).await.expect("Failed to seed refresh record into the store.");
}

fn build_descriptor(server: &MockServer) -> ProviderDescriptor {
	let provider_id = ProviderId::new("mock-refresh")
		.expect("Provider identifier should be valid for refresh test.");

	ProviderDescriptor::builder(provider_id)
		.authorization_endpoint(
			Url::parse(&server.url("/authorize"))
				.expect("Mock authorize endpoint should parse successfully."),
		)
		.token_endpoint(
			Url::parse(&server.url("/token"))
				.expect("Mock token endpoint should parse successfully."),
		)
		.support_grants([GrantType::RefreshToken])
		.preferred_client_auth_method(ClientAuthMethod::ClientSecretPost)
		.build()
		.expect("Provider descriptor should build successfully.")
}

#[tokio::test]
async fn refresh_rotates_tokens_and_updates_store() {
	let server = MockServer::start_async().await;
	let descriptor = build_descriptor(&server);
	let (broker, store) = build_reqwest_test_broker(descriptor.clone(), CLIENT_ID, CLIENT_SECRET);
	let tenant = TenantId::new("tenant-refresh")
		.expect("Tenant identifier should be valid for refresh test.");
	let principal = PrincipalId::new("principal-refresh")
		.expect("Principal identifier should be valid for refresh test.");
	let scope = ScopeSet::new(["openid", "profile"])
		.expect("Scope set should be valid for refresh rotation test.");

	seed_record(
		&store,
		&descriptor,
		tenant.clone(),
		principal.clone(),
		scope.clone(),
		"rotating-access",
		"rotating-refresh",
		Duration::seconds(30),
	)
	.await;

	let mock = server
		.mock_async(|when, then| {
			when.method(POST).path("/token");
			then.status(200)
				.header("content-type", "application/json")
				.body(
					"{\"access_token\":\"access-new\",\"refresh_token\":\"refresh-new\",\"token_type\":\"bearer\",\"expires_in\":1800}",
				);
		})
		.await;
	let record = broker
		.refresh_access_token(CachedTokenRequest::new(
			tenant.clone(),
			principal.clone(),
			scope.clone(),
		))
		.await
		.expect("Refresh token rotation should succeed.");

	mock.assert_async().await;

	assert_eq!(record.access_token.expose(), "access-new");
	assert_eq!(record.refresh_token.as_ref().map(|secret| secret.expose()), Some("refresh-new"));

	let stored = store
		.fetch(&record.family, &record.scope)
		.await
		.expect("Token store fetch should succeed.")
		.expect("Record should remain present after refresh.");

	assert_eq!(stored.access_token.expose(), "access-new");
	assert_eq!(stored.refresh_token.as_ref().map(|secret| secret.expose()), Some("refresh-new"));
}

#[tokio::test]
async fn refresh_singleflight_hits_provider_once() {
	let server = MockServer::start_async().await;
	let descriptor = build_descriptor(&server);
	let (broker, store) = build_reqwest_test_broker(descriptor.clone(), CLIENT_ID, CLIENT_SECRET);
	let tenant = TenantId::new("tenant-singleflight")
		.expect("Tenant identifier should be valid for singleflight test.");
	let principal = PrincipalId::new("principal-singleflight")
		.expect("Principal identifier should be valid for singleflight test.");
	let scope = ScopeSet::new(["email"]).expect("Scope set should be valid for singleflight test.");

	seed_record(
		&store,
		&descriptor,
		tenant.clone(),
		principal.clone(),
		scope.clone(),
		"access-soon-expiring",
		"refresh-soon-expiring",
		Duration::seconds(5),
	)
	.await;

	let mock = server
		.mock_async(|when, then| {
			when.method(POST).path("/token");
			then.status(200)
				.header("content-type", "application/json")
				.body(
					"{\"access_token\":\"access-singleflight\",\"refresh_token\":\"refresh-singleflight\",\"token_type\":\"bearer\",\"expires_in\":3600}",
				);
		})
		.await;
	let request = CachedTokenRequest::new(tenant.clone(), principal.clone(), scope.clone())
		.with_preemptive_window(Duration::minutes(5));
	let (first, second): (Result<TokenRecord>, Result<TokenRecord>) = tokio::join!(
		broker.refresh_access_token(request.clone()),
		broker.refresh_access_token(request),
	);
	let first = first.expect("First refresh request should succeed.");
	let second = second.expect("Second refresh request should succeed.");

	assert_eq!(first.access_token.expose(), "access-singleflight");
	assert_eq!(second.access_token.expose(), "access-singleflight");

	mock.assert_calls_async(1).await;
}

#[tokio::test]
async fn refresh_invalid_grant_revokes_record() {
	let server = MockServer::start_async().await;
	let descriptor = build_descriptor(&server);
	let (broker, store) = build_reqwest_test_broker(descriptor.clone(), CLIENT_ID, CLIENT_SECRET);
	let tenant = TenantId::new("tenant-revoked")
		.expect("Tenant identifier should be valid for revoke test.");
	let principal = PrincipalId::new("principal-revoked")
		.expect("Principal identifier should be valid for revoke test.");
	let scope = ScopeSet::new(["repo", "notifications"])
		.expect("Scope set should be valid for revoke test.");

	seed_record(
		&store,
		&descriptor,
		tenant.clone(),
		principal.clone(),
		scope.clone(),
		"access-revoke",
		"refresh-revoke",
		Duration::minutes(10),
	)
	.await;

	let mock = server
		.mock_async(|when, then| {
			when.method(POST).path("/token");
			then.status(400)
				.header("content-type", "application/json")
				.body("{\"error\":\"invalid_grant\"}");
		})
		.await;
	let err = broker
		.refresh_access_token(
			CachedTokenRequest::new(tenant.clone(), principal.clone(), scope.clone())
				.force_refresh(),
		)
		.await
		.expect_err("Invalid grant errors should surface to the caller.");

	assert!(matches!(err, Error::InvalidGrant { .. }));

	mock.assert_async().await;

	let mut family = TokenFamily::new(tenant.clone(), principal.clone());

	family.provider = Some(descriptor.id.clone());

	let revoked = store
		.fetch(&family, &scope)
		.await
		.expect("Token store fetch should succeed for revoked record.")
		.expect("Revoked record should remain present for inspection.");

	assert!(revoked.revoked_at.is_some());
}
