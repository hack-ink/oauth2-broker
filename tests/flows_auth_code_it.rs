#![cfg(feature = "reqwest")]

// crates.io
use httpmock::prelude::*;
// self
use oauth2_broker::{
	_preludet::*,
	auth::{PrincipalId, ProviderId, ScopeSet, TenantId, TokenFamily},
	flows::PkceCodeChallengeMethod,
	provider::{ClientAuthMethod, GrantType, ProviderDescriptor},
	store::BrokerStore,
};

const CLIENT_ID: &str = "client-it";
const CLIENT_SECRET: &str = "secret-it";

fn build_descriptor(server: &MockServer) -> ProviderDescriptor {
	let provider_id = ProviderId::new("mock-http")
		.expect("Provider identifier should be valid for auth code test.");

	ProviderDescriptor::builder(provider_id)
		.authorization_endpoint(
			Url::parse(&server.url("/authorize"))
				.expect("Mock authorization endpoint should parse successfully."),
		)
		.token_endpoint(
			Url::parse(&server.url("/token"))
				.expect("Mock token endpoint should parse successfully."),
		)
		.support_grant(GrantType::AuthorizationCode)
		.preferred_client_auth_method(ClientAuthMethod::ClientSecretPost)
		.build()
		.expect("Provider descriptor should build successfully.")
}

#[tokio::test]
async fn start_authorization_and_exchange_successfully_save_tokens() {
	let server = MockServer::start_async().await;
	let descriptor = build_descriptor(&server);
	let (broker, store) = build_reqwest_test_broker(descriptor, CLIENT_ID, CLIENT_SECRET);
	let tenant =
		TenantId::new("tenant-123").expect("Tenant identifier should be valid for auth code test.");
	let principal = PrincipalId::new("principal-456")
		.expect("Principal identifier should be valid for auth code test.");
	let scope = ScopeSet::new(["openid", "profile"])
		.expect("Scope set should be valid for auth code test.");
	let redirect_uri = Url::parse("https://app.example.com/callback")
		.expect("Redirect URI should parse successfully.");
	let session = broker
		.start_authorization(tenant.clone(), principal.clone(), scope.clone(), redirect_uri.clone())
		.expect("Authorization session should start successfully.");

	assert_eq!(&session.tenant, &tenant);
	assert_eq!(&session.principal, &principal);
	assert_eq!(&session.scope, &scope);
	assert_eq!(&session.redirect_uri, &redirect_uri);
	assert_eq!(session.code_challenge_method(), PkceCodeChallengeMethod::S256);
	assert_eq!(session.state.len(), 32);
	assert!(session.validate_state(session.state.as_str()).is_ok());

	let authorize_pairs: HashMap<_, _> = session.authorize_url.query_pairs().into_owned().collect();

	assert_eq!(authorize_pairs.get("response_type"), Some(&"code".into()));
	assert_eq!(authorize_pairs.get("client_id"), Some(&CLIENT_ID.into()));
	assert_eq!(authorize_pairs.get("redirect_uri"), Some(&redirect_uri.as_str().into()));
	assert!(authorize_pairs.contains_key("code_challenge"));
	assert_eq!(authorize_pairs.get("code_challenge_method"), Some(&"S256".into()));

	let mock = server
		.mock_async(|when, then| {
			when.method(POST)
				.path("/token")
				.header("content-type", "application/x-www-form-urlencoded");
			then
				.status(200)
				.header("content-type", "application/json")
				.body(
					"{\"access_token\":\"access-success\",\"refresh_token\":\"refresh-success\",\"token_type\":\"bearer\",\"expires_in\":3600}",
				);
		})
		.await;
	let record = broker
		.exchange_code(session, "valid-code")
		.await
		.expect("Authorization code exchange should succeed.");

	mock.assert_async().await;

	assert_eq!(record.access_token.expose(), "access-success");
	assert_eq!(
		record.refresh_token.as_ref().map(|secret| secret.expose()),
		Some("refresh-success")
	);
	assert_eq!(&record.scope, &scope);
	assert!(record.expires_at > record.issued_at);

	let stored = store
		.fetch(&record.family, &record.scope)
		.await
		.expect("Token store fetch should succeed.")
		.expect("Stored record should remain present.");

	assert_eq!(stored.access_token.expose(), record.access_token.expose());
	assert_eq!(
		stored.refresh_token.as_ref().map(|secret| secret.expose()),
		record.refresh_token.as_ref().map(|secret| secret.expose())
	);
}

#[tokio::test]
async fn exchange_code_classifies_invalid_grant_errors() {
	let server = MockServer::start_async().await;
	let descriptor = build_descriptor(&server);
	let (broker, store) = build_reqwest_test_broker(descriptor, CLIENT_ID, CLIENT_SECRET);
	let tenant =
		TenantId::new("tenant-err").expect("Tenant identifier should be valid for error test.");
	let principal = PrincipalId::new("principal-err")
		.expect("Principal identifier should be valid for error test.");
	let scope =
		ScopeSet::new(["email"]).expect("Scope set should be valid for error classification test.");
	let redirect_uri = Url::parse("https://app.example.com/callback")
		.expect("Redirect URI should parse successfully.");
	let session = broker
		.start_authorization(tenant.clone(), principal.clone(), scope.clone(), redirect_uri)
		.expect("Authorization session should start successfully.");
	let mock = server
		.mock_async(|when, then| {
			when.method(POST).path("/token");
			then.status(400)
				.header("content-type", "application/json")
				.body("{\"error\":\"invalid_grant\",\"error_description\":\"already used\"}");
		})
		.await;
	let err = broker
		.exchange_code(session, "stale-code")
		.await
		.expect_err("Invalid grant errors should be classified correctly.");

	assert!(matches!(err, Error::InvalidGrant { .. }));

	mock.assert_async().await;

	let maybe_record = store
		.fetch(&TokenFamily::new(tenant, principal), &scope)
		.await
		.expect("Token store fetch should succeed.");

	assert!(
		maybe_record.is_none(),
		"Store must not retain records when the authorization code exchange fails."
	);
}
