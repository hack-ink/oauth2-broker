//! Walks through launching an authorization-code + PKCE session and persisting it for the
//! redirect handler to later exchange.

// std
use std::{collections::HashMap, sync::Arc};
// crates.io
use color_eyre::Result;
use url::Url;
// self
use oauth2_broker::{
	auth::{PrincipalId, ProviderId, ScopeSet, TenantId},
	flows::Broker,
	provider::{DefaultProviderStrategy, GrantType, ProviderDescriptor, ProviderStrategy},
	store::{BrokerStore, MemoryStore},
};

fn main() -> Result<()> {
	color_eyre::install()?;

	let store: Arc<dyn BrokerStore> = Arc::new(MemoryStore::default());
	let strategy: Arc<dyn ProviderStrategy> = Arc::new(DefaultProviderStrategy);
	let descriptor = ProviderDescriptor::builder(ProviderId::new("demo-provider")?)
		.authorization_endpoint(Url::parse("https://provider.example.com/authorize")?)
		.token_endpoint(Url::parse("https://provider.example.com/token")?)
		.support_grants([GrantType::AuthorizationCode, GrantType::RefreshToken])
		.build()?;
	let broker =
		Broker::new(store, descriptor, strategy, "demo-client").with_client_secret("demo-secret");
	let scope = ScopeSet::new(["openid", "profile"])?;
	let session = broker.start_authorization(
		TenantId::new("tenant-acme")?,
		PrincipalId::new("user-123")?,
		scope,
		Url::parse("https://app.example.com/oauth/callback")?,
	)?;

	println!("Send your user to {}.", &session.authorize_url);
	println!(
		"PKCE challenge ({:?}): {}.",
		session.code_challenge_method(),
		session.code_challenge()
	);

	let mut sessions: HashMap<String, _> = HashMap::new();

	sessions.insert(session.state.clone(), session.clone());

	// Simulate the redirect handler looking up the stored session by `state`.
	let returned_state = session.state.clone();

	if let Some(stashed) = sessions.remove(&returned_state) {
		stashed.validate_state(&returned_state)?;
		println!(
			"Validated state for tenant {} and principal {}.",
			&stashed.tenant, &stashed.principal
		);
		println!("Persist this session to call Broker::exchange_code during the callback.");
	} else {
		eprintln!("State `{returned_state}` was not recognized.");
	}

	Ok(())
}
