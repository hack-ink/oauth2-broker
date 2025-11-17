// self
use oauth2_broker::{
	_preludet::*,
	auth::ProviderId,
	provider::{
		ClientAuthMethod, DefaultProviderStrategy, GrantType, ProviderDescriptor,
		ProviderDescriptorBuilder, ProviderDescriptorError, ProviderErrorContext,
		ProviderErrorKind, ProviderQuirks, ProviderStrategy,
	},
};

fn url(value: &str) -> Url {
	Url::parse(value).expect("Failed to parse mock provider URL.")
}

fn builder(id: &str) -> ProviderDescriptorBuilder {
	let provider_id =
		ProviderId::new(id).expect("Failed to build provider identifier for mock descriptor.");

	ProviderDescriptor::builder(provider_id)
}

#[test]
fn descriptor_rejects_insecure_endpoints_and_missing_grants() {
	let err = builder("mock-insecure")
		.authorization_endpoint(url("http://example.com/auth"))
		.token_endpoint(url("https://example.com/token"))
		.build()
		.expect_err("Descriptor builder should reject missing grants.");

	assert!(matches!(err, ProviderDescriptorError::NoSupportedGrants));

	let err = builder("mock")
		.authorization_endpoint(url("http://example.com/auth"))
		.token_endpoint(url("https://example.com/token"))
		.support_grant(GrantType::AuthorizationCode)
		.build()
		.expect_err("Descriptor builder should reject insecure authorization endpoints.");

	assert!(matches!(
		err,
		ProviderDescriptorError::InsecureEndpoint { endpoint: "authorization", .. }
	));
}

#[test]
fn descriptor_support_helpers_cover_flags() {
	let descriptor = builder("grants")
		.authorization_endpoint(url("https://example.com/auth"))
		.token_endpoint(url("https://example.com/token"))
		.revocation_endpoint(url("https://example.com/revoke"))
		.support_grants([GrantType::AuthorizationCode, GrantType::RefreshToken])
		.preferred_client_auth_method(ClientAuthMethod::ClientSecretPost)
		.build()
		.expect("Descriptor builder should succeed for secure endpoints.");

	assert!(descriptor.supports(GrantType::AuthorizationCode));
	assert!(descriptor.supports(GrantType::RefreshToken));
	assert!(!descriptor.supports(GrantType::ClientCredentials));
	assert_eq!(descriptor.endpoints.authorization.as_str(), "https://example.com/auth");
	assert_eq!(descriptor.endpoints.token.as_str(), "https://example.com/token");
	assert_eq!(
		descriptor
			.endpoints
			.revocation
			.as_ref()
			.expect("Revocation endpoint should be populated when configured.")
			.as_str(),
		"https://example.com/revoke",
	);
	assert_eq!(descriptor.preferred_client_auth_method, ClientAuthMethod::ClientSecretPost);
	assert!(!descriptor.quirks.pkce_required);
	assert!(descriptor.quirks.exact_redirect_match);
	assert_eq!(descriptor.quirks.scope_delimiter, ' ');
}

#[test]
fn pkce_requirement_requires_auth_code_grant() {
	let quirks = ProviderQuirks { pkce_required: true, ..ProviderQuirks::default() };
	let err = builder("pkce")
		.authorization_endpoint(url("https://example.com/auth"))
		.token_endpoint(url("https://example.com/token"))
		.support_grant(GrantType::RefreshToken)
		.quirks(quirks)
		.build()
		.expect_err("PKCE requirement should enforce support for authorization code grants.");

	assert!(matches!(err, ProviderDescriptorError::PkceRequiredWithoutAuthorizationCode));
}

#[test]
fn default_strategy_prefers_oauth_error_fields() {
	let strategy = DefaultProviderStrategy;
	let ctx = ProviderErrorContext::new(GrantType::AuthorizationCode)
		.with_http_status(400)
		.with_oauth_error("invalid_grant");
	let classified = strategy.classify_token_error(&ctx);

	assert_eq!(classified, ProviderErrorKind::InvalidGrant);

	let ctx = ProviderErrorContext::new(GrantType::AuthorizationCode)
		.with_http_status(401)
		.with_oauth_error("invalid_client");
	let classified = strategy.classify_token_error(&ctx);

	assert_eq!(classified, ProviderErrorKind::InvalidClient);
}

#[test]
fn default_strategy_falls_back_to_status_and_body() {
	let strategy = DefaultProviderStrategy;
	let ctx = ProviderErrorContext::new(GrantType::ClientCredentials).with_http_status(401);

	assert_eq!(strategy.classify_token_error(&ctx), ProviderErrorKind::InvalidClient);

	let body_ctx = ProviderErrorContext::new(GrantType::RefreshToken)
		.with_body_preview("error=insufficient_scope");

	assert_eq!(strategy.classify_token_error(&body_ctx), ProviderErrorKind::InsufficientScope);

	let network_ctx = ProviderErrorContext::network_failure(GrantType::RefreshToken);

	assert_eq!(strategy.classify_token_error(&network_ctx), ProviderErrorKind::Transient);
}

#[test]
fn default_strategy_reads_error_description_when_missing_error_code() {
	let strategy = DefaultProviderStrategy;
	let ctx = ProviderErrorContext::new(GrantType::AuthorizationCode)
		.with_http_status(500)
		.with_error_description("invalid_grant: code already used");

	assert_eq!(strategy.classify_token_error(&ctx), ProviderErrorKind::InvalidGrant);
}

#[test]
fn custom_strategy_can_augment_token_requests() {
	struct AudienceStrategy;
	impl ProviderStrategy for AudienceStrategy {
		fn classify_token_error(&self, _ctx: &ProviderErrorContext) -> ProviderErrorKind {
			ProviderErrorKind::InvalidGrant
		}

		fn augment_token_request(&self, grant: GrantType, form: &mut BTreeMap<String, String>) {
			form.insert("audience".into(), format!("for:{grant}"));
		}
	}

	let strategy = AudienceStrategy;
	let mut form = BTreeMap::new();

	form.insert("grant_type".into(), "client_credentials".into());
	strategy.augment_token_request(GrantType::ClientCredentials, &mut form);

	assert_eq!(form.get("audience").map(String::as_str), Some("for:client_credentials"));
}
