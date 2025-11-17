//! Internal OAuth client facade abstractions.

pub use oauth2;

// std
use std::borrow::Cow;
// crates.io
use oauth2::{
	AuthType, AuthUrl, AuthorizationCode, ClientId, ClientSecret, EndpointNotSet, EndpointSet,
	HttpClientError, PkceCodeVerifier, RedirectUrl, RefreshToken, RequestTokenError, Scope,
	TokenResponse, TokenUrl,
	basic::{BasicClient, BasicErrorResponse, BasicRequestTokenError},
};
// self
use crate::{
	_prelude::*,
	auth::{ScopeSet, TokenFamily, TokenRecord},
	error::{ConfigError, TransientError, TransportError},
	http::{ReqwestHttpClient, ResponseMetadata, ResponseMetadataSlot, TokenHttpClient},
	provider::{
		ClientAuthMethod, GrantType, ProviderDescriptor, ProviderErrorContext, ProviderErrorKind,
		ProviderStrategy,
	},
};

type ConfiguredBasicClient =
	BasicClient<EndpointSet, EndpointNotSet, EndpointNotSet, EndpointNotSet, EndpointSet>;
type FacadeTokenResponse = oauth2::basic::BasicTokenResponse;
type FacadeFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T>> + 'a + Send>>;

/// Maps HTTP transport failures into broker [`Error`] values.
pub trait TransportErrorMapper<E>
where
	Self: 'static + Send + Sync,
	E: 'static + Send + Sync + StdError,
{
	/// Converts an [`HttpClientError`] emitted by the transport into a broker error.
	fn map_transport_error(
		&self,
		strategy: &dyn ProviderStrategy,
		grant: GrantType,
		metadata: Option<&ResponseMetadata>,
		error: HttpClientError<E>,
	) -> Error;
}

/// Default mapper for reqwest-backed transports.
#[derive(Clone, Debug, Default)]
pub struct ReqwestTransportErrorMapper;
impl TransportErrorMapper<ReqwestError> for ReqwestTransportErrorMapper {
	fn map_transport_error(
		&self,
		strategy: &dyn ProviderStrategy,
		grant: GrantType,
		meta: Option<&ResponseMetadata>,
		err: HttpClientError<ReqwestError>,
	) -> Error {
		match err {
			HttpClientError::Reqwest(inner) => map_reqwest_error(strategy, grant, meta, *inner),
			HttpClientError::Http(inner) => ConfigError::from(inner).into(),
			HttpClientError::Io(inner) => TransportError::Io(inner).into(),
			HttpClientError::Other(message) => map_generic_transport_error(meta, message),
			_ => map_unknown_transport_error(meta),
		}
	}
}

pub(crate) trait OAuth2Facade {
	fn exchange_client_credentials<'a, 'strategy, 'scopes, 'params>(
		&'a self,
		strategy: &'strategy dyn ProviderStrategy,
		family: TokenFamily,
		scopes: &'scopes [&'scopes str],
		extra_params: &'params [(String, String)],
	) -> FacadeFuture<'a, TokenRecord>
	where
		'strategy: 'a,
		'scopes: 'a,
		'params: 'a;

	fn refresh_token<'a, 'strategy, 'refresh, 'scope>(
		&'a self,
		strategy: &'strategy dyn ProviderStrategy,
		family: TokenFamily,
		refresh_token: &'refresh str,
		requested_scope: &'scope ScopeSet,
	) -> FacadeFuture<'a, (TokenRecord, Option<String>)>
	where
		'strategy: 'a,
		'refresh: 'a,
		'scope: 'a;

	fn exchange_authorization_code<'a, 'strategy, 'code, 'pkce, 'scope, 'redirect>(
		&'a self,
		strategy: &'strategy dyn ProviderStrategy,
		family: TokenFamily,
		code: &'code str,
		pkce_verifier: &'pkce str,
		requested_scope: &'scope ScopeSet,
		redirect_uri: &'redirect Url,
	) -> FacadeFuture<'a, TokenRecord>
	where
		'strategy: 'a,
		'code: 'a,
		'pkce: 'a,
		'scope: 'a,
		'redirect: 'a;
}

pub(crate) struct BasicFacade<C = ReqwestHttpClient, M = ReqwestTransportErrorMapper>
where
	C: ?Sized + TokenHttpClient,
	M: ?Sized + TransportErrorMapper<C::TransportError>,
{
	oauth_client: ConfiguredBasicClient,
	http_client: Arc<C>,
	error_mapper: Arc<M>,
}
impl<C, M> BasicFacade<C, M>
where
	C: ?Sized + TokenHttpClient,
	M: ?Sized + TransportErrorMapper<C::TransportError>,
{
	pub(super) fn new(
		oauth_client: ConfiguredBasicClient,
		http_client: impl Into<Arc<C>>,
		error_mapper: impl Into<Arc<M>>,
	) -> Self {
		Self { oauth_client, http_client: http_client.into(), error_mapper: error_mapper.into() }
	}

	pub(crate) fn from_descriptor(
		descriptor: &ProviderDescriptor,
		client_id: &str,
		client_secret: Option<&str>,
		redirect_uri: Option<&Url>,
		http_client: impl Into<Arc<C>>,
		error_mapper: impl Into<Arc<M>>,
	) -> Result<Self> {
		let auth_url = AuthUrl::new(descriptor.endpoints.authorization.to_string())
			.map_err(|source| ConfigError::InvalidDescriptor { source })?;
		let token_url = TokenUrl::new(descriptor.endpoints.token.to_string())
			.map_err(|source| ConfigError::InvalidDescriptor { source })?;
		let secret =
			if matches!(descriptor.preferred_client_auth_method, ClientAuthMethod::NoneWithPkce) {
				None
			} else {
				client_secret.map(|value| ClientSecret::new(value.to_owned()))
			};
		let mut oauth_client = BasicClient::new(ClientId::new(client_id.to_owned()))
			.set_auth_uri(auth_url)
			.set_token_uri(token_url);

		if let Some(secret) = secret {
			oauth_client = oauth_client.set_client_secret(secret);
		}
		if let Some(redirect) = redirect_uri {
			let redirect_url = RedirectUrl::new(redirect.to_string())
				.map_err(|source| ConfigError::InvalidDescriptor { source })?;

			oauth_client = oauth_client.set_redirect_uri(redirect_url);
		}

		if matches!(descriptor.preferred_client_auth_method, ClientAuthMethod::ClientSecretPost) {
			oauth_client = oauth_client.set_auth_type(AuthType::RequestBody);
		}

		Ok(Self::new(oauth_client, http_client, error_mapper))
	}
}
impl<C, M> OAuth2Facade for BasicFacade<C, M>
where
	C: ?Sized + TokenHttpClient,
	M: ?Sized + TransportErrorMapper<C::TransportError>,
{
	fn exchange_client_credentials<'a, 'strategy, 'scopes, 'params>(
		&'a self,
		strategy: &'strategy dyn ProviderStrategy,
		family: TokenFamily,
		scopes: &'scopes [&'scopes str],
		extra_params: &'params [(String, String)],
	) -> FacadeFuture<'a, TokenRecord>
	where
		'strategy: 'a,
		'scopes: 'a,
		'params: 'a,
	{
		let meta = ResponseMetadataSlot::default();

		Box::pin(async move {
			let instrumented = self.http_client.with_metadata(meta.clone());
			let requested_scope =
				ScopeSet::new(scopes.iter().copied()).map_err(ConfigError::from)?;
			let mut request = self.oauth_client.exchange_client_credentials();

			for scope in scopes {
				request = request.add_scope(Scope::new((*scope).to_owned()));
			}
			for (key, value) in extra_params {
				request = request.add_extra_param(key, value);
			}

			let response = request.request_async(&instrumented).await.map_err(|err| {
				map_request_error(
					strategy,
					GrantType::ClientCredentials,
					meta.take(),
					err,
					self.error_mapper.as_ref(),
				)
			})?;

			map_standard_token_response(family, requested_scope, response)
		})
	}

	fn refresh_token<'a, 'strategy, 'refresh, 'scope>(
		&'a self,
		strategy: &'strategy dyn ProviderStrategy,
		family: TokenFamily,
		refresh_token: &'refresh str,
		requested_scope: &'scope ScopeSet,
	) -> FacadeFuture<'a, (TokenRecord, Option<String>)>
	where
		'strategy: 'a,
		'refresh: 'a,
		'scope: 'a,
	{
		let meta = ResponseMetadataSlot::default();

		Box::pin(async move {
			let instrumented = self.http_client.with_metadata(meta.clone());
			let refresh_secret = RefreshToken::new(refresh_token.to_owned());
			let mut request = self.oauth_client.exchange_refresh_token(&refresh_secret);

			if !requested_scope.is_empty() {
				for scope in requested_scope.iter() {
					request = request.add_scope(Scope::new(scope.to_owned()));
				}
			}

			let response = request.request_async(&instrumented).await.map_err(|err| {
				map_request_error(
					strategy,
					GrantType::RefreshToken,
					meta.take(),
					err,
					self.error_mapper.as_ref(),
				)
			})?;

			map_refresh_token_response(family, requested_scope, response)
		})
	}

	fn exchange_authorization_code<'a, 'strategy, 'code, 'pkce, 'scope, 'redirect>(
		&'a self,
		strategy: &'strategy dyn ProviderStrategy,
		family: TokenFamily,
		code: &'code str,
		pkce_verifier: &'pkce str,
		requested_scope: &'scope ScopeSet,
		redirect_uri: &'redirect Url,
	) -> FacadeFuture<'a, TokenRecord>
	where
		'strategy: 'a,
		'code: 'a,
		'pkce: 'a,
		'scope: 'a,
		'redirect: 'a,
	{
		let meta = ResponseMetadataSlot::default();

		Box::pin(async move {
			let instrumented = self.http_client.with_metadata(meta.clone());
			let mut request = self
				.oauth_client
				.exchange_code(AuthorizationCode::new(code.to_owned()))
				.set_pkce_verifier(PkceCodeVerifier::new(pkce_verifier.to_owned()));

			if !requested_scope.is_empty() {
				request = request.add_extra_param("scope", requested_scope.normalized());
			}

			let redirect_url = RedirectUrl::new(redirect_uri.to_string())
				.map_err(|err| ConfigError::InvalidRedirect { source: err })?;

			request = request.set_redirect_uri(Cow::Owned(redirect_url));

			let response = request.request_async(&instrumented).await.map_err(|err| {
				map_request_error(
					strategy,
					GrantType::AuthorizationCode,
					meta.take(),
					err,
					self.error_mapper.as_ref(),
				)
			})?;
			let expires_in = response.expires_in().ok_or(ConfigError::MissingExpiresIn)?.as_secs();
			let expires_in =
				i64::try_from(expires_in).map_err(|_| ConfigError::ExpiresInOutOfRange)?;

			if expires_in <= 0 {
				return Err(ConfigError::NonPositiveExpiresIn.into());
			}

			if let Some(scopes) = response.scopes() {
				let returned = ScopeSet::new(scopes.iter().map(|scope| scope.as_ref()))
					.map_err(ConfigError::from)?;
				if returned != *requested_scope {
					return Err(ConfigError::ScopesChanged { grant: "authorization_code" }.into());
				}
			}

			let issued_at = OffsetDateTime::now_utc();
			let mut builder = TokenRecord::builder(family, requested_scope.clone())
				.access_token(response.access_token().secret().to_owned())
				.issued_at(issued_at)
				.expires_in(Duration::seconds(expires_in));

			if let Some(refresh) = response.refresh_token() {
				builder = builder.refresh_token(refresh.secret().to_owned());
			}

			builder.build().map_err(|e| ConfigError::from(e).into())
		})
	}
}

fn map_standard_token_response(
	family: TokenFamily,
	scope: ScopeSet,
	response: FacadeTokenResponse,
) -> Result<TokenRecord> {
	let expires_in = response.expires_in().ok_or(ConfigError::MissingExpiresIn)?.as_secs();
	let expires_in = i64::try_from(expires_in).map_err(|_| ConfigError::ExpiresInOutOfRange)?;

	if expires_in <= 0 {
		return Err(ConfigError::NonPositiveExpiresIn.into());
	}

	if let Some(scopes) = response.scopes() {
		let returned =
			ScopeSet::new(scopes.iter().map(|scope| scope.as_ref())).map_err(ConfigError::from)?;
		if returned != scope {
			return Err(ConfigError::ScopesChanged { grant: "client_credentials" }.into());
		}
	}

	let issued_at = OffsetDateTime::now_utc();

	TokenRecord::builder(family, scope)
		.access_token(response.access_token().secret().to_owned())
		.issued_at(issued_at)
		.expires_in(Duration::seconds(expires_in))
		.build()
		.map_err(|err| ConfigError::from(err).into())
}

fn map_refresh_token_response(
	family: TokenFamily,
	requested_scope: &ScopeSet,
	response: FacadeTokenResponse,
) -> Result<(TokenRecord, Option<String>)> {
	let expires_in = response.expires_in().ok_or(ConfigError::MissingExpiresIn)?.as_secs();
	let expires_in = i64::try_from(expires_in).map_err(|_| ConfigError::ExpiresInOutOfRange)?;

	if expires_in <= 0 {
		return Err(ConfigError::NonPositiveExpiresIn.into());
	}

	if let Some(scopes) = response.scopes() {
		let returned =
			ScopeSet::new(scopes.iter().map(|scope| scope.as_ref())).map_err(ConfigError::from)?;
		if returned != *requested_scope {
			return Err(ConfigError::ScopesChanged { grant: "refresh_token" }.into());
		}
	}

	let issued_at = OffsetDateTime::now_utc();
	let mut builder = TokenRecord::builder(family, requested_scope.clone())
		.access_token(response.access_token().secret().to_owned())
		.issued_at(issued_at)
		.expires_in(Duration::seconds(expires_in));
	let new_refresh = response.refresh_token().map(|token| token.secret().to_owned());

	if let Some(secret) = &new_refresh {
		builder = builder.refresh_token(secret.clone());
	}

	let record = builder.build().map_err(ConfigError::from)?;

	Ok((record, new_refresh))
}

fn map_request_error<E, M>(
	strategy: &dyn ProviderStrategy,
	grant: GrantType,
	meta: Option<ResponseMetadata>,
	err: BasicRequestTokenError<HttpClientError<E>>,
	mapper: &M,
) -> Error
where
	E: 'static + Send + Sync + StdError,
	M: ?Sized + TransportErrorMapper<E>,
{
	let meta_ref = meta.as_ref();

	match err {
		RequestTokenError::ServerResponse(response) =>
			map_server_response_error(strategy, grant, response, meta_ref),
		RequestTokenError::Request(error) =>
			map_transport_error(strategy, grant, meta_ref, error, mapper),
		RequestTokenError::Parse(error, _body) =>
			TransientError::TokenResponseParse { source: error, status: meta_status(meta_ref) }
				.into(),
		RequestTokenError::Other(message) => TransientError::TokenEndpoint {
			message: format!("Token endpoint returned an unexpected response: {message}."),
			status: meta_status(meta_ref),
			retry_after: meta_retry_after(meta_ref),
		}
		.into(),
	}
}

fn map_server_response_error(
	strategy: &dyn ProviderStrategy,
	grant: GrantType,
	response: BasicErrorResponse,
	meta: Option<&ResponseMetadata>,
) -> Error {
	let mut ctx =
		ProviderErrorContext::new(grant).with_oauth_error(response.error().as_ref().to_string());
	if let Some(description) = response.error_description() {
		ctx = ctx.with_error_description(description.clone());
	}

	if let Some(status) = meta_status(meta) {
		ctx = ctx.with_http_status(status);
	}

	let classification = strategy.classify_token_error(&ctx);
	let message = if let Some(description) = response.error_description() {
		format!("Token endpoint returned an OAuth error: {description}.")
	} else {
		format!("Token endpoint returned an OAuth error: {}.", response.error().as_ref())
	};

	match classification {
		ProviderErrorKind::InvalidGrant => Error::InvalidGrant { reason: message },
		ProviderErrorKind::InvalidClient => Error::InvalidClient { reason: message },
		ProviderErrorKind::InsufficientScope => Error::InsufficientScope { reason: message },
		ProviderErrorKind::Transient => TransientError::TokenEndpoint {
			message,
			status: meta_status(meta),
			retry_after: meta_retry_after(meta),
		}
		.into(),
	}
}

fn map_transport_error<E, M>(
	strategy: &dyn ProviderStrategy,
	grant: GrantType,
	meta: Option<&ResponseMetadata>,
	err: HttpClientError<E>,
	mapper: &M,
) -> Error
where
	E: 'static + Send + Sync + StdError,
	M: ?Sized + TransportErrorMapper<E>,
{
	mapper.map_transport_error(strategy, grant, meta, err)
}

fn map_reqwest_error(
	strategy: &dyn ProviderStrategy,
	grant: GrantType,
	meta: Option<&ResponseMetadata>,
	err: ReqwestError,
) -> Error {
	// Strategy reserved for future use.
	let _ = (strategy, grant);

	if err.is_builder() {
		return ConfigError::from(err).into();
	}
	if err.is_timeout() {
		return TransientError::TokenEndpoint {
			message: "Request timed out while calling the token endpoint.".into(),
			status: meta_status(meta).or_else(|| reqwest_status(&err)),
			retry_after: meta_retry_after(meta),
		}
		.into();
	}

	TransportError::from(err).into()
}

fn map_generic_transport_error(meta: Option<&ResponseMetadata>, message: impl Display) -> Error {
	TransientError::TokenEndpoint {
		message: format!("HTTP client error occurred while calling the token endpoint: {message}."),
		status: meta_status(meta),
		retry_after: meta_retry_after(meta),
	}
	.into()
}

fn map_unknown_transport_error(meta: Option<&ResponseMetadata>) -> Error {
	TransientError::TokenEndpoint {
		message: "HTTP client error occurred while calling the token endpoint.".into(),
		status: meta_status(meta),
		retry_after: meta_retry_after(meta),
	}
	.into()
}

fn meta_status(meta: Option<&ResponseMetadata>) -> Option<u16> {
	meta.and_then(|value| value.status)
}

fn meta_retry_after(meta: Option<&ResponseMetadata>) -> Option<Duration> {
	meta.and_then(|value| value.retry_after)
}

fn reqwest_status(err: &ReqwestError) -> Option<u16> {
	err.status().map(|code| code.as_u16())
}

#[cfg(test)]
mod tests {
	// self
	use super::*;
	use crate::auth::ProviderId;

	fn descriptor(method: ClientAuthMethod) -> ProviderDescriptor {
		let provider_id =
			ProviderId::new("test-provider").expect("Failed to construct provider identifier.");

		ProviderDescriptor::builder(provider_id)
			.authorization_endpoint(
				Url::parse("https://example.com/oauth2/authorize")
					.expect("Failed to parse authorization endpoint URL."),
			)
			.token_endpoint(
				Url::parse("https://example.com/oauth2/token")
					.expect("Failed to parse token endpoint URL."),
			)
			.support_grant(GrantType::AuthorizationCode)
			.preferred_client_auth_method(method)
			.build()
			.expect("Failed to build provider descriptor.")
	}

	#[test]
	fn builds_basic_auth_client() {
		let descriptor = descriptor(ClientAuthMethod::ClientSecretBasic);
		let redirect =
			Url::parse("https://example.com/callback").expect("Failed to parse redirect URI.");
		let result = <BasicFacade<ReqwestHttpClient, ReqwestTransportErrorMapper>>::from_descriptor(
			&descriptor,
			"client-id",
			Some("secret"),
			Some(&redirect),
			Arc::new(ReqwestHttpClient::default()),
			Arc::new(ReqwestTransportErrorMapper),
		);

		assert!(result.is_ok());
	}

	#[test]
	fn builds_post_auth_client() {
		let descriptor = descriptor(ClientAuthMethod::ClientSecretPost);
		let result = <BasicFacade<ReqwestHttpClient, ReqwestTransportErrorMapper>>::from_descriptor(
			&descriptor,
			"client-id",
			Some("secret"),
			None,
			Arc::new(ReqwestHttpClient::default()),
			Arc::new(ReqwestTransportErrorMapper),
		);

		assert!(result.is_ok());
	}

	#[test]
	fn builds_pkce_client_without_secret() {
		let descriptor = descriptor(ClientAuthMethod::NoneWithPkce);
		let result = <BasicFacade<ReqwestHttpClient, ReqwestTransportErrorMapper>>::from_descriptor(
			&descriptor,
			"public-client",
			Some("ignored-secret"),
			None,
			Arc::new(ReqwestHttpClient::default()),
			Arc::new(ReqwestTransportErrorMapper),
		);

		assert!(result.is_ok());
	}
}
