//! High-level flow orchestrators powered by the broker facade.

pub mod auth_code_pkce;
pub mod common;
pub mod refresh;

mod client_credentials;

pub use auth_code_pkce::*;
pub use common::*;
pub use refresh::*;

// self
use crate::{
	_prelude::*,
	http::TokenHttpClient,
	oauth::TransportErrorMapper,
	provider::{ProviderDescriptor, ProviderStrategy},
	store::{BrokerStore, StoreKey},
};
#[cfg(feature = "reqwest")]
use crate::{http::ReqwestHttpClient, oauth::ReqwestTransportErrorMapper};

#[cfg(feature = "reqwest")]
/// Broker specialized for the crate's default reqwest transport stack.
pub type ReqwestBroker = Broker<ReqwestHttpClient, ReqwestTransportErrorMapper>;

/// Coordinates OAuth 2.0 flows against a single provider descriptor.
///
/// The broker owns the HTTP client, token store, provider descriptor, and strategy
/// references so individual flow implementations can focus on grant-specific logic
/// (state + PKCE generation, code exchanges, refresh rotations, etc.). Client
/// credentials are stored alongside the descriptor so client-auth methods can be
/// applied consistently across token endpoints.
#[derive(Clone)]
pub struct Broker<C, M>
where
	C: ?Sized + TokenHttpClient,
	M: ?Sized + TransportErrorMapper<C::TransportError>,
{
	/// HTTP client wrapper used for every outbound provider request.
	pub http_client: Arc<C>,
	/// Mapper applied to transport-layer errors before surfacing them to callers.
	pub transport_mapper: Arc<M>,
	/// Token store implementation that persists issued secrets.
	pub store: Arc<dyn BrokerStore>,
	/// Provider descriptor that defines OAuth endpoints and quirks.
	pub descriptor: ProviderDescriptor,
	/// Strategy responsible for provider-specific token request adjustments.
	pub strategy: Arc<dyn ProviderStrategy>,
	/// OAuth 2.0 client identifier used in every grant.
	pub client_id: String,
	/// Optional client secret for confidential authentication methods.
	pub client_secret: Option<String>,
	/// Shared metrics recorder for refresh flow outcomes.
	pub refresh_metrics: Arc<RefreshMetrics>,
	flow_guards: Arc<Mutex<HashMap<StoreKey, Arc<AsyncMutex<()>>>>>,
}
impl<C, M> Broker<C, M>
where
	C: ?Sized + TokenHttpClient,
	M: ?Sized + TransportErrorMapper<C::TransportError>,
{
	/// Creates a broker that reuses the caller-provided transport + mapper pair.
	pub fn with_http_client(
		store: Arc<dyn BrokerStore>,
		descriptor: ProviderDescriptor,
		strategy: Arc<dyn ProviderStrategy>,
		client_id: impl Into<String>,
		http_client: impl Into<Arc<C>>,
		mapper: impl Into<Arc<M>>,
	) -> Self {
		Self {
			http_client: http_client.into(),
			transport_mapper: mapper.into(),
			store,
			descriptor,
			strategy,
			client_id: client_id.into(),
			client_secret: None,
			flow_guards: Default::default(),
			refresh_metrics: Default::default(),
		}
	}

	/// Sets or replaces the client secret used for confidential client auth modes.
	pub fn with_client_secret(mut self, secret: impl Into<String>) -> Self {
		self.client_secret = Some(secret.into());

		self
	}
}
#[cfg(feature = "reqwest")]
impl Broker<ReqwestHttpClient, ReqwestTransportErrorMapper> {
	/// Creates a new broker for the provided descriptor and client identifier.
	///
	/// The broker provisions its own reqwest-backed transport so callers do not need
	/// to pass HTTP handles explicitly. Use [`Broker::with_client_secret`] to attach a confidential
	/// client secret when the descriptor prefers `client_secret_basic` or
	/// `client_secret_post`.
	pub fn new(
		store: Arc<dyn BrokerStore>,
		descriptor: ProviderDescriptor,
		strategy: Arc<dyn ProviderStrategy>,
		client_id: impl Into<String>,
	) -> Self {
		Self::with_http_client(
			store,
			descriptor,
			strategy,
			client_id,
			ReqwestHttpClient::default(),
			Arc::new(ReqwestTransportErrorMapper),
		)
	}
}
impl<C, M> Debug for Broker<C, M>
where
	C: ?Sized + TokenHttpClient,
	M: ?Sized + TransportErrorMapper<C::TransportError>,
{
	fn fmt(&self, f: &mut Formatter) -> FmtResult {
		f.debug_struct("Broker")
			.field("descriptor", &self.descriptor)
			.field("client_id", &self.client_id)
			.field("client_secret_set", &self.client_secret.is_some())
			.finish()
	}
}
