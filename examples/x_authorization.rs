//! Interactive Authorization Code + PKCE walkthrough for X (Twitter).
//!
//! The example prints the authorize URL, waits for the user to paste the returned
//! `state` and `code` parameters via stdin, optionally exchanges the code for
//! tokens, and can send a tweet so the bearer token is exercised end-to-end.

// std
use std::{
	io::{self, Write},
	sync::Arc,
};
// crates.io
use color_eyre::Result;
use serde_json::{self, json};
use url::Url;
// self
use oauth2_broker::{
	auth::{PrincipalId, ProviderId, ScopeSet, TenantId},
	flows::Broker,
	provider::{
		DefaultProviderStrategy, GrantType, ProviderDescriptor, ProviderQuirks, ProviderStrategy,
	},
	reqwest::Client,
	store::{BrokerStore, MemoryStore},
};

#[tokio::main]
async fn main() -> Result<()> {
	color_eyre::install()?;

	let client_id = prompt_with_default("Enter your X client ID", Some("demo-x-client"))?;
	let client_secret = prompt_optional("Enter your X client secret (leave blank for PKCE-only)")?;
	let redirect_input = prompt_with_default(
		"Enter the redirect URI registered with X",
		Some("https://app.example.com/x/callback"),
	)?;
	let redirect_uri = Url::parse(&redirect_input)?;
	let store: Arc<dyn BrokerStore> = Arc::new(MemoryStore::default());
	let strategy: Arc<dyn ProviderStrategy> = Arc::new(DefaultProviderStrategy);
	let descriptor = ProviderDescriptor::builder(ProviderId::new("x-com")?)
		.authorization_endpoint(Url::parse("https://x.com/i/oauth2/authorize")?)
		.token_endpoint(Url::parse("https://api.x.com/2/oauth2/token")?)
		.support_grants([GrantType::AuthorizationCode, GrantType::RefreshToken])
		.quirks(ProviderQuirks { pkce_required: true, ..ProviderQuirks::default() })
		.build()?;
	let scope = ScopeSet::new(["tweet.read", "tweet.write", "users.read", "offline.access"])?;
	let mut broker = Broker::new(store, descriptor, strategy, client_id);

	if let Some(secret) = client_secret.filter(|value| !value.is_empty()) {
		broker = broker.with_client_secret(secret);
	}

	let session = broker.start_authorization(
		TenantId::new("tenant-acme")?,
		PrincipalId::new("user-1729")?,
		scope,
		redirect_uri,
	)?;

	println!("Authorize URL: {}", &session.authorize_url);
	println!(
		"PKCE challenge ({:?}): {}.",
		session.code_challenge_method(),
		session.code_challenge()
	);
	println!(
		"After X redirects back to your app, copy the `state` and `code` query parameters and paste them here."
	);

	let returned_state = prompt_with_default(
		"State (press Enter to reuse the generated value)",
		Some(session.state.as_str()),
	)?;

	session.validate_state(&returned_state)?;

	let authorization_code =
		prompt_optional("Authorization code (leave blank to skip the live token exchange)")?;

	if let Some(code) = authorization_code {
		let record = broker.exchange_code(session, code).await?;
		println!("Access token: {}", record.access_token.expose());
		if let Some(refresh) = record.refresh_token.as_ref() {
			println!("Refresh token: {}", refresh.expose());
		} else {
			println!("Provider did not return a refresh token.");
		}
		println!("Expires at: {}", record.expires_at);
		let tweet_prompt = prompt_optional(
			"Tweet text (leave blank to skip posting to https://api.x.com/2/tweets)",
		)?;
		if let Some(text) = tweet_prompt {
			post_tweet(record.access_token.expose(), &text).await?;
		} else {
			println!("Tweet skipped; token exchange confirmed.");
		}
		return Ok(());
	}

	println!("Authorization code not provided; skipping token exchange.");
	println!(
		"Persist the session details and call Broker::exchange_code once a real authorization code is available."
	);

	Ok(())
}

fn prompt_with_default(message: &str, default: Option<&str>) -> Result<String> {
	loop {
		if let Some(value) = default {
			print!("{message} [{value}]: ");
		} else {
			print!("{message}: ");
		}

		io::stdout().flush()?;

		let mut input = String::new();

		io::stdin().read_line(&mut input)?;

		let trimmed = input.trim();

		if trimmed.is_empty() {
			if let Some(value) = default {
				return Ok(value.to_owned());
			}
		} else {
			return Ok(trimmed.to_owned());
		}
	}
}

fn prompt_optional(message: &str) -> Result<Option<String>> {
	print!("{message}: ");

	io::stdout().flush()?;

	let mut input = String::new();

	io::stdin().read_line(&mut input)?;

	let trimmed = input.trim();

	if trimmed.is_empty() { Ok(None) } else { Ok(Some(trimmed.to_owned())) }
}

async fn post_tweet(access_token: &str, text: &str) -> Result<()> {
	let client = Client::new();

	println!("Posting tweet: {text}");

	let payload = serde_json::to_string(&json!({ "text": text }))?;
	let response = client
		.post("https://api.x.com/2/tweets")
		.bearer_auth(access_token)
		.header("content-type", "application/json")
		.body(payload)
		.send()
		.await?;
	let status = response.status();
	let body = response.text().await?;

	println!("Tweet response ({status}): {body}");

	Ok(())
}
