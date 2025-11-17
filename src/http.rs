//! Transport primitives for OAuth token exchanges.
//!
//! The module exposes [`TokenHttpClient`] alongside [`ResponseMetadata`] and
//! [`ResponseMetadataSlot`] so downstream crates can integrate custom HTTP clients
//! without losing the broker's instrumentation hooks. Implementations call
//! [`ResponseMetadataSlot::take`] before dispatching a request and
//! [`ResponseMetadataSlot::store`] once an HTTP status or retry hint is known,
//! enabling `map_request_error` to classify failures with consistent metadata.

// std
use std::ops::Deref;
// crates.io
use oauth2::{AsyncHttpClient, HttpClientError, HttpRequest, HttpResponse};
#[cfg(feature = "reqwest")] use reqwest::header::{HeaderMap, RETRY_AFTER};
#[cfg(feature = "reqwest")] use time::format_description::well_known::Rfc2822;
// self
use crate::_prelude::*;

/// Abstraction over HTTP transports capable of executing OAuth token exchanges while
/// publishing response metadata to the broker's instrumentation pipeline.
///
/// The trait acts as the broker's only dependency on an HTTP stack. Callers provide
/// an implementation (typically behind `Arc<T>` where `T: TokenHttpClient`) and the broker
/// requests short-lived [`AsyncHttpClient`] handles that each carry a clone of a
/// [`ResponseMetadataSlot`]. Implementations must be `Send + Sync + 'static` so they
/// can be shared across broker instances without additional wrappers, and the handles
/// they return must own whatever state is required so their request futures remain
/// `Send` for the lifetime of the in-flight operation. This lets facade callers box
/// the async blocks without worrying about borrowed transports.
pub trait TokenHttpClient
where
	Self: 'static + Send + Sync,
{
	/// Concrete error emitted by the underlying transport.
	type TransportError: 'static + Send + Sync + StdError;

	/// [`AsyncHttpClient`] handle tied to a [`ResponseMetadataSlot`].
	///
	/// Each handle must satisfy `Send + Sync` so broker futures can hop executors without
	/// cloning transports unnecessarily. The request future returned by
	/// [`AsyncHttpClient::call`] must also be `Send` so the facade's boxed futures
	/// inherit the same guarantee.
	type Handle: for<'c> AsyncHttpClient<
			'c,
			Error = HttpClientError<Self::TransportError>,
			Future: 'c + Send,
		>
		+ 'static
		+ Send
		+ Sync;

	/// Builds an [`AsyncHttpClient`] handle that records outcomes in `slot`.
	///
	/// # Metadata Contract
	///
	/// - Call [`ResponseMetadataSlot::take`] before submitting the HTTP request so stale
	///   information never leaks across retries.
	/// - Once an HTTP response (successful or erroneous) provides status headers, save them with
	///   [`ResponseMetadataSlot::store`].
	/// - Never retain the slot clone beyond the lifetime of the returned handle; the handle itself
	///   enforces borrowing rules for the transport.
	fn with_metadata(&self, slot: ResponseMetadataSlot) -> Self::Handle;
}

/// Captures metadata from the most recent HTTP response for downstream error mapping.
///
/// Additional metadata fields may be added in future releases, so downstream code
/// should construct values using field names instead of struct update syntax.
#[derive(Clone, Debug, Default)]
pub struct ResponseMetadata {
	/// HTTP status code returned by the token endpoint, if available.
	pub status: Option<u16>,
	/// Retry-After hint expressed as a relative duration.
	pub retry_after: Option<Duration>,
}

/// Thread-safe slot for sharing [`ResponseMetadata`] between transport and error layers.
///
/// The broker creates a fresh slot for each token request and reads the captured
/// metadata immediately after `oauth2` resolves. Transport implementations borrow
/// the slot just long enough to call [`store`](ResponseMetadataSlot::store) and must
/// keep ownership with the broker.
#[derive(Clone, Debug, Default)]
pub struct ResponseMetadataSlot(Arc<Mutex<Option<ResponseMetadata>>>);
impl ResponseMetadataSlot {
	/// Stores new metadata for the current request.
	pub fn store(&self, meta: ResponseMetadata) {
		*self.0.lock() = Some(meta);
	}

	/// Returns the captured metadata, if any, consuming it from the slot.
	///
	/// Custom HTTP clients should invoke this helper before performing a request to
	/// ensure traces from prior attempts never leak into the new invocation.
	pub fn take(&self) -> Option<ResponseMetadata> {
		self.0.lock().take()
	}
}

/// Thin wrapper around [`ReqwestClient`] so shared HTTP behavior lives in one place.
/// Token requests should not follow redirects, matching OAuth 2.0 guidance that token
/// endpoints return results directly instead of delegating to another URI. Configure
/// any custom [`ReqwestClient`] to disable redirect following, because the broker
/// passes this client into the `oauth2` crate when it builds the facade layer.
#[cfg(feature = "reqwest")]
#[derive(Clone, Default)]
pub struct ReqwestHttpClient(pub ReqwestClient);
#[cfg(feature = "reqwest")]
impl ReqwestHttpClient {
	/// Wraps an existing reqwest [`ReqwestClient`].
	pub fn with_client(client: ReqwestClient) -> Self {
		Self(client)
	}

	/// Builds an instrumented HTTP client that captures response metadata.
	pub(crate) fn instrumented(&self, slot: ResponseMetadataSlot) -> InstrumentedHandle {
		InstrumentedHandle::new(self.0.clone(), slot)
	}
}
#[cfg(feature = "reqwest")]
impl AsRef<ReqwestClient> for ReqwestHttpClient {
	fn as_ref(&self) -> &ReqwestClient {
		&self.0
	}
}
#[cfg(feature = "reqwest")]
impl Deref for ReqwestHttpClient {
	type Target = ReqwestClient;

	fn deref(&self) -> &Self::Target {
		&self.0
	}
}

#[cfg(feature = "reqwest")]
/// Instrumented adapter that implements [`AsyncHttpClient`] for reqwest.
pub(crate) struct InstrumentedHttpClient {
	client: ReqwestClient,
	slot: ResponseMetadataSlot,
}
#[cfg(feature = "reqwest")]
impl InstrumentedHttpClient {
	fn new(client: ReqwestClient, slot: ResponseMetadataSlot) -> Self {
		Self { client, slot }
	}
}

#[cfg(feature = "reqwest")]
/// Public handle returned by [`ReqwestHttpClient`] that satisfies [`TokenHttpClient`].
#[derive(Clone)]
pub struct InstrumentedHandle(Arc<InstrumentedHttpClient>);
#[cfg(feature = "reqwest")]
impl InstrumentedHandle {
	fn new(client: ReqwestClient, slot: ResponseMetadataSlot) -> Self {
		Self(Arc::new(InstrumentedHttpClient::new(client, slot)))
	}
}
#[cfg(feature = "reqwest")]
impl<'c> AsyncHttpClient<'c> for InstrumentedHandle {
	type Error = HttpClientError<ReqwestError>;
	type Future =
		Pin<Box<dyn Future<Output = Result<HttpResponse, Self::Error>> + 'c + Send + Sync>>;

	fn call(&'c self, request: HttpRequest) -> Self::Future {
		let client = Arc::clone(&self.0);

		Box::pin(async move {
			client.slot.take();

			let response = client
				.client
				.execute(request.try_into().map_err(Box::new)?)
				.await
				.map_err(Box::new)?;
			let status = response.status();
			let headers = response.headers().to_owned();
			let retry_after = parse_retry_after(&headers);

			client.slot.store(ResponseMetadata { status: Some(status.as_u16()), retry_after });

			let mut response_new =
				HttpResponse::new(response.bytes().await.map_err(Box::new)?.to_vec());

			*response_new.status_mut() = status;
			*response_new.headers_mut() = headers;

			Ok(response_new)
		})
	}
}
#[cfg(feature = "reqwest")]
impl TokenHttpClient for ReqwestHttpClient {
	type Handle = InstrumentedHandle;
	type TransportError = ReqwestError;

	fn with_metadata(&self, slot: ResponseMetadataSlot) -> Self::Handle {
		self.instrumented(slot)
	}
}

#[cfg(feature = "reqwest")]
fn parse_retry_after(headers: &HeaderMap) -> Option<Duration> {
	let value = headers.get(RETRY_AFTER)?;
	let raw = value.to_str().ok()?.trim();

	if let Ok(secs) = raw.parse::<u64>() {
		return Some(Duration::seconds(secs as i64));
	}
	if let Ok(moment) = OffsetDateTime::parse(raw, &Rfc2822) {
		let delta = moment - OffsetDateTime::now_utc();

		if delta.is_positive() {
			return Some(delta);
		}
	}

	None
}
