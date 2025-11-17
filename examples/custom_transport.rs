//! Demonstrates registering a custom HTTP client and mapper that emit non-reqwest errors.
//!
//! 1. Implement [`TokenHttpClient`] so the transport records [`ResponseMetadata`] via the provided
//!    [`ResponseMetadataSlot`].
//! 2. Provide a [`TransportErrorMapper`] that understands both the transport error type and the
//!    captured metadata.
//! 3. Wrap both handles in `Arc` and pass them to [`Broker::with_http_client`].
//! 4. Map the resulting [`HttpClientError`] variants back into the broker's [`Error`] type.

// std
use std::{
	error::Error as StdError,
	fmt::{Display, Formatter, Result as FmtResult},
	future::Future,
	pin::Pin,
	sync::Arc,
};
// crates.io
use color_eyre::Result;
use time::Duration;
use url::Url;
// self
use oauth2_broker::{
	auth::{PrincipalId, ProviderId, ScopeSet, TenantId},
	error::{Error, TransientError},
	flows::{Broker, CachedTokenRequest},
	http::{ResponseMetadata, ResponseMetadataSlot, TokenHttpClient},
	oauth::{
		TransportErrorMapper,
		oauth2::{AsyncHttpClient, HttpClientError, HttpRequest, HttpResponse},
	},
	provider::{DefaultProviderStrategy, GrantType, ProviderDescriptor, ProviderStrategy},
	store::{BrokerStore, MemoryStore},
};

#[tokio::main]
async fn main() -> Result<()> {
	color_eyre::install()?;

	let store: Arc<dyn BrokerStore> = Arc::new(MemoryStore::default());
	let strategy: Arc<dyn ProviderStrategy> = Arc::new(DefaultProviderStrategy);
	let descriptor = ProviderDescriptor::builder(ProviderId::new("mock-provider")?)
		.authorization_endpoint(Url::parse("https://provider.example.com/authorize")?)
		.token_endpoint(Url::parse("https://provider.example.com/token")?)
		.support_grant(GrantType::ClientCredentials)
		.build()?;
	let mapper = <Arc<MockTransportErrorMapper>>::new(MockTransportErrorMapper);
	let broker: Broker<MockHttpClient, MockTransportErrorMapper> = Broker::with_http_client(
		Arc::clone(&store),
		descriptor.clone(),
		Arc::clone(&strategy),
		"demo-client",
		Arc::new(MockHttpClient::default()),
		Arc::clone(&mapper),
	)
	.with_client_secret("demo-secret");
	let request = CachedTokenRequest::new(
		TenantId::new("tenant-acme")?,
		PrincipalId::new("svc-router")?,
		ScopeSet::new(["profile.read"])?,
	);
	let record = broker.client_credentials(request.clone()).await?;

	println!("Access token issued by the mock transport: {}.", record.access_token.expose());

	let failing_client =
		Arc::new(MockHttpClient::transport_error(MockTransportError::DnsFailure {
			host: "provider.example.com",
		}));
	let failing_broker: Broker<MockHttpClient, MockTransportErrorMapper> =
		Broker::with_http_client(
			Arc::clone(&store),
			descriptor.clone(),
			Arc::clone(&strategy),
			"demo-client",
			failing_client,
			Arc::clone(&mapper),
		)
		.with_client_secret("demo-secret");
	let failing_request = request.clone();

	match failing_broker.client_credentials(failing_request).await {
		Ok(_) => println!("Mock transport unexpectedly succeeded."),
		Err(e) => println!("Transport error mapped by the broker: {e}."),
	}

	let other_client = Arc::new(MockHttpClient::other_error("upstream connection closed"));
	let other_broker: Broker<MockHttpClient, MockTransportErrorMapper> =
		Broker::with_http_client(store, descriptor, strategy, "demo-client", other_client, mapper)
			.with_client_secret("demo-secret");

	match other_broker.client_credentials(request).await {
		Ok(_) => println!("Mock transport unexpectedly produced a token."),
		Err(e) => println!("An HttpClientError::Other variant made it through the mapper: {e}."),
	}

	Ok(())
}

#[derive(Clone, Debug)]
enum MockTransportError {
	DnsFailure {
		host: &'static str,
	},
	#[allow(unused)]
	BackendTimeout,
}
impl Display for MockTransportError {
	fn fmt(&self, f: &mut Formatter) -> FmtResult {
		match self {
			Self::DnsFailure { host } => write!(f, "DNS lookup failed for {host}"),
			Self::BackendTimeout => write!(f, "Token endpoint timed out"),
		}
	}
}
impl StdError for MockTransportError {}

#[derive(Clone)]
enum MockBehavior {
	Success,
	TransportError(MockTransportError),
	Other(&'static str),
}

#[derive(Clone)]
struct MockHttpClient {
	behavior: MockBehavior,
}
impl MockHttpClient {
	fn success() -> Self {
		Self { behavior: MockBehavior::Success }
	}

	fn transport_error(error: MockTransportError) -> Self {
		Self { behavior: MockBehavior::TransportError(error) }
	}

	fn other_error(message: &'static str) -> Self {
		Self { behavior: MockBehavior::Other(message) }
	}
}
impl Default for MockHttpClient {
	fn default() -> Self {
		Self::success()
	}
}
impl TokenHttpClient for MockHttpClient {
	type Handle = MockHttpHandle;
	type TransportError = MockTransportError;

	fn with_metadata(&self, slot: ResponseMetadataSlot) -> Self::Handle {
		MockHttpHandle { slot, behavior: self.behavior.clone() }
	}
}

struct MockHttpHandle {
	slot: ResponseMetadataSlot,
	behavior: MockBehavior,
}
impl<'a> AsyncHttpClient<'a> for MockHttpHandle {
	type Error = HttpClientError<MockTransportError>;
	type Future =
		Pin<Box<dyn Future<Output = Result<HttpResponse, Self::Error>> + 'a + Send + Sync>>;

	fn call(&'a self, _request: HttpRequest) -> Self::Future {
		let slot = self.slot.clone();
		let behavior = self.behavior.clone();

		Box::pin(async move {
			slot.take();

			match behavior {
				MockBehavior::Success => {
					slot.store(ResponseMetadata {
						status: Some(200),
						retry_after: Some(Duration::seconds(1)),
					});

					Ok(HttpResponse::new(
						b"{\"access_token\":\"mock-access\",\"token_type\":\"bearer\",\"expires_in\":900}".
							to_vec(),
					))
				},
				MockBehavior::TransportError(error) => {
					slot.store(ResponseMetadata {
						status: Some(503),
						retry_after: Some(Duration::seconds(2)),
					});

					// The oauth2 crate keeps the `Reqwest` variant name even though the
					// boxed payload can be any transport error, so we wrap the mock error
					// inside `HttpClientError::Reqwest` for mapper consumption.
					Err(HttpClientError::Reqwest(Box::new(error)))
				},
				MockBehavior::Other(message) => {
					slot.store(ResponseMetadata { status: None, retry_after: None });

					Err(HttpClientError::Other(message.to_owned()))
				},
			}
		})
	}
}

#[derive(Clone, Default)]
struct MockTransportErrorMapper;
impl TransportErrorMapper<MockTransportError> for MockTransportErrorMapper {
	fn map_transport_error(
		&self,
		_strategy: &dyn ProviderStrategy,
		grant: GrantType,
		metadata: Option<&ResponseMetadata>,
		error: HttpClientError<MockTransportError>,
	) -> Error {
		let grant_name = grant.as_str();
		let (message, status, retry_after) = match error {
			HttpClientError::Reqwest(inner) => match *inner {
				MockTransportError::DnsFailure { host } => (
					format!(
						"Mock transport error while executing the {grant_name} grant: DNS lookup failed for {host}."
					),
					metadata.and_then(|meta| meta.status),
					metadata.and_then(|meta| meta.retry_after),
				),
				MockTransportError::BackendTimeout => (
					format!(
						"Mock transport error while executing the {grant_name} grant: the token endpoint timed out."
					),
					metadata.and_then(|meta| meta.status),
					metadata.and_then(|meta| meta.retry_after),
				),
			},
			HttpClientError::Other(text) => (
				format!("Mock transport error while executing the {grant_name} grant: {text}."),
				metadata.and_then(|meta| meta.status),
				metadata.and_then(|meta| meta.retry_after),
			),
			_ => (
				format!("Mock transport error while executing the {grant_name} grant."),
				metadata.and_then(|meta| meta.status),
				metadata.and_then(|meta| meta.retry_after),
			),
		};

		TransientError::TokenEndpoint { message, status, retry_after }.into()
	}
}
