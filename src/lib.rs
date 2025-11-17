//! Rust’s turnkey OAuth 2.0 broker—spin up multi-tenant flows, CAS-smart token stores, and
//! transport-aware observability in one crate built for production.

#![deny(clippy::all, missing_docs, unused_crate_dependencies)]

pub mod auth;
pub mod error;
pub mod ext;
pub mod flows;
pub mod http;
pub mod oauth;
pub mod obs;
pub mod provider;
pub mod store;
#[cfg(all(any(test, feature = "test"), feature = "reqwest"))]
pub mod _preludet {
	//! Convenience re-exports and helpers for integration tests; enabled via `cfg(test)` or the
	//! `test` crate feature.

	pub use crate::_prelude::*;

	// self
	use crate::{
		flows::Broker,
		http::ReqwestHttpClient,
		oauth::ReqwestTransportErrorMapper,
		provider::{DefaultProviderStrategy, ProviderDescriptor, ProviderStrategy},
		store::{BrokerStore, MemoryStore},
	};

	/// Broker type alias used by reqwest-backed integration tests.
	pub type ReqwestTestBroker = Broker<ReqwestHttpClient, ReqwestTransportErrorMapper>;

	/// Builds a reqwest HTTP client that accepts the self-signed certificates produced by
	/// `httpmock` during tests.
	pub fn test_reqwest_http_client() -> ReqwestHttpClient {
		let client = ReqwestClient::builder()
			.danger_accept_invalid_certs(true)
			.danger_accept_invalid_hostnames(true)
			.build()
			.expect("Failed to build insecure Reqwest client for tests.");

		ReqwestHttpClient::with_client(client)
	}

	/// Constructs a [`Broker`] backed by an in-memory store, default provider strategy, and the
	/// reqwest transport used across integration tests.
	pub fn build_reqwest_test_broker(
		descriptor: ProviderDescriptor,
		client_id: &str,
		client_secret: &str,
	) -> (ReqwestTestBroker, Arc<MemoryStore>) {
		let store_backend = Arc::new(MemoryStore::default());
		let store: Arc<dyn BrokerStore> = store_backend.clone();
		let strategy: Arc<dyn ProviderStrategy> = Arc::new(DefaultProviderStrategy);
		let http_client = test_reqwest_http_client();
		let mapper = Arc::new(ReqwestTransportErrorMapper);
		let broker =
			Broker::with_http_client(store, descriptor, strategy, client_id, http_client, mapper)
				.with_client_secret(client_secret);

		(broker, store_backend)
	}
}

mod _prelude {
	pub use std::{
		collections::{BTreeMap, HashMap, hash_map::DefaultHasher},
		error::Error as StdError,
		fmt::{Debug, Display, Formatter, Result as FmtResult},
		future::Future,
		hash::{Hash, Hasher},
		pin::Pin,
		str::FromStr,
		sync::Arc,
	};

	pub use async_lock::Mutex as AsyncMutex;
	pub use parking_lot::{Mutex, RwLock};
	#[cfg(feature = "reqwest")]
	pub use reqwest::{Client as ReqwestClient, Error as ReqwestError};
	pub use serde::{Deserialize, Serialize};
	pub use thiserror::Error as ThisError;
	pub use time::{Duration, OffsetDateTime};
	pub use url::Url;

	pub use crate::error::{Error, Result};
}

#[cfg(feature = "reqwest")] pub use reqwest;
pub use url;
#[cfg(all(test, feature = "reqwest"))] use {color_eyre as _, httpmock as _};
