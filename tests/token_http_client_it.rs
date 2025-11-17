// self
use oauth2_broker::{
	_preludet::*,
	auth::{PrincipalId, ProviderId, ScopeSet, TenantId},
	error::{ConfigError, Error, Result, TransientError, TransportError},
	flows::{Broker, CachedTokenRequest},
	http::{ResponseMetadata, ResponseMetadataSlot, TokenHttpClient},
	oauth::{
		TransportErrorMapper,
		oauth2::{AsyncHttpClient, HttpClientError, HttpRequest, HttpResponse},
	},
	provider::{
		ClientAuthMethod, DefaultProviderStrategy, GrantType, ProviderDescriptor, ProviderStrategy,
	},
	store::{BrokerStore, MemoryStore},
};

#[derive(Debug)]
enum FakeTransportError {
	Throttled,
}
impl Display for FakeTransportError {
	fn fmt(&self, f: &mut Formatter) -> FmtResult {
		match self {
			Self::Throttled => write!(f, "Transport throttled."),
		}
	}
}
impl StdError for FakeTransportError {}

#[derive(Clone, Copy)]
struct FakeHttpClient {
	retry_after: Duration,
}
impl FakeHttpClient {
	fn throttled(retry_after: Duration) -> Self {
		Self { retry_after }
	}
}
impl TokenHttpClient for FakeHttpClient {
	type Handle = FakeHttpHandle;
	type TransportError = FakeTransportError;

	fn with_metadata(&self, slot: ResponseMetadataSlot) -> Self::Handle {
		FakeHttpHandle { slot, retry_after: self.retry_after }
	}
}

struct FakeHttpHandle {
	slot: ResponseMetadataSlot,
	retry_after: Duration,
}
impl<'a> AsyncHttpClient<'a> for FakeHttpHandle {
	type Error = HttpClientError<FakeTransportError>;
	type Future =
		Pin<Box<dyn Future<Output = Result<HttpResponse, Self::Error>> + 'a + Send + Sync>>;

	fn call(&'a self, _request: HttpRequest) -> Self::Future {
		let slot = self.slot.clone();
		let retry_after = self.retry_after;

		Box::pin(async move {
			assert!(
				slot.take().is_none(),
				"ResponseMetadataSlot must be clear before dispatching a request."
			);
			slot.store(ResponseMetadata { status: Some(429), retry_after: Some(retry_after) });

			Err(HttpClientError::Reqwest(Box::new(FakeTransportError::Throttled)))
		})
	}
}

#[derive(Clone, Default)]
struct RecordingTransportErrorMapper {
	metadata: Arc<Mutex<Vec<Option<ResponseMetadata>>>>,
}
impl RecordingTransportErrorMapper {
	fn recorded_metadata(&self) -> Vec<Option<ResponseMetadata>> {
		self.metadata.lock().clone()
	}
}
impl TransportErrorMapper<FakeTransportError> for RecordingTransportErrorMapper {
	fn map_transport_error(
		&self,
		strategy: &dyn ProviderStrategy,
		grant: GrantType,
		meta: Option<&ResponseMetadata>,
		err: HttpClientError<FakeTransportError>,
	) -> Error {
		let status = meta.and_then(|value| value.status);
		let retry_after = meta.and_then(|value| value.retry_after);

		self.metadata.lock().push(meta.cloned());

		let _ = (strategy, grant);

		match err {
			HttpClientError::Reqwest(inner) => TransientError::TokenEndpoint {
				message: format!("Fake transport error: {inner}"),
				status,
				retry_after,
			}
			.into(),
			HttpClientError::Http(inner) => ConfigError::from(inner).into(),
			HttpClientError::Io(inner) => TransportError::Io(inner).into(),
			HttpClientError::Other(message) => TransientError::TokenEndpoint {
				message: format!(
					"HTTP client error occurred while calling the token endpoint: {message}"
				),
				status,
				retry_after,
			}
			.into(),
			other => TransientError::TokenEndpoint {
				message: format!(
					"Unhandled HTTP client error variant while calling the token endpoint: {other:?}"
				),
				status,
				retry_after,
			}
			.into(),
		}
	}
}

fn build_descriptor() -> ProviderDescriptor {
	let provider_id =
		ProviderId::new("mock-token-http").expect("Failed to build mock provider identifier.");

	ProviderDescriptor::builder(provider_id)
		.authorization_endpoint(
			Url::parse("https://mock.example.com/authorize")
				.expect("Failed to parse mock authorization endpoint URL."),
		)
		.token_endpoint(
			Url::parse("https://mock.example.com/token")
				.expect("Failed to parse mock token endpoint URL."),
		)
		.support_grant(GrantType::ClientCredentials)
		.preferred_client_auth_method(ClientAuthMethod::ClientSecretPost)
		.build()
		.expect("Failed to build mock provider descriptor.")
}

#[tokio::test]
async fn fake_token_http_client_surfaces_metadata() {
	let descriptor = build_descriptor();
	let store_backend = Arc::new(MemoryStore::default());
	let store: Arc<dyn BrokerStore> = store_backend;
	let strategy: Arc<dyn ProviderStrategy> = Arc::new(DefaultProviderStrategy);
	let http_client = Arc::new(FakeHttpClient::throttled(Duration::seconds(5)));
	let mapper = Arc::new(RecordingTransportErrorMapper::default());
	let broker: Broker<FakeHttpClient, RecordingTransportErrorMapper> = Broker::with_http_client(
		store,
		descriptor,
		strategy,
		"throttled-client",
		http_client,
		mapper,
	)
	.with_client_secret("throttled-secret");
	let request = CachedTokenRequest::new(
		TenantId::new("mock-tenant").expect("Failed to build mock tenant identifier."),
		PrincipalId::new("mock-principal").expect("Failed to build mock principal identifier."),
		ScopeSet::new(["profile.read"]).expect("Failed to build mock scope set."),
	);
	let err = broker
		.client_credentials(request)
		.await
		.expect_err("Request should be throttled with HTTP 429.");

	match err {
		Error::Transient(TransientError::TokenEndpoint { status, retry_after, .. }) => {
			assert_eq!(status, Some(429));
			assert_eq!(retry_after, Some(Duration::seconds(5)));
		},
		other => panic!("Unexpected error variant: {other:?}."),
	}
}

#[tokio::test]
async fn fake_mapper_captures_response_metadata() {
	let descriptor = build_descriptor();
	let store_backend = Arc::new(MemoryStore::default());
	let store: Arc<dyn BrokerStore> = store_backend;
	let strategy: Arc<dyn ProviderStrategy> = Arc::new(DefaultProviderStrategy);
	let http_client = Arc::new(FakeHttpClient::throttled(Duration::seconds(30)));
	let mapper = Arc::new(RecordingTransportErrorMapper::default());
	let broker: Broker<FakeHttpClient, RecordingTransportErrorMapper> = Broker::with_http_client(
		store,
		descriptor,
		strategy,
		"metadata-client",
		http_client,
		mapper.clone(),
	)
	.with_client_secret("metadata-secret");
	let request = CachedTokenRequest::new(
		TenantId::new("fake-tenant").expect("Failed to build fake tenant identifier."),
		PrincipalId::new("fake-principal").expect("Failed to build fake principal identifier."),
		ScopeSet::new(["profile.read"]).expect("Failed to build fake scope set."),
	);
	let _ = broker
		.client_credentials(request)
		.await
		.expect_err("Request should be throttled with HTTP 429.");
	let observed = mapper.recorded_metadata();

	assert_eq!(observed.len(), 1, "Mapper must record a single request.");

	let meta = observed
		.first()
		.and_then(|value| value.clone())
		.expect("Response metadata should be recorded exactly once.");

	assert_eq!(meta.status, Some(429));
	assert_eq!(meta.retry_after, Some(Duration::seconds(30)));
}
