<div align="center">

# oauth2-broker

Rust’s turnkey OAuth 2.0 broker—spin up multi-tenant flows, CAS-smart token stores, and transport-aware observability in one crate built for production.

[![License](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Docs](https://img.shields.io/docsrs/oauth2-broker)](https://docs.rs/oauth2-broker)
[![Rust](https://github.com/hack-ink/oauth2-broker/actions/workflows/rust.yml/badge.svg?branch=main)](https://github.com/hack-ink/oauth2-broker/actions/workflows/rust.yml)
[![Release](https://github.com/hack-ink/oauth2-broker/actions/workflows/release.yml/badge.svg)](https://github.com/hack-ink/oauth2-broker/actions/workflows/release.yml)
[![GitHub tag (latest by date)](https://img.shields.io/github/v/tag/hack-ink/oauth2-broker)](https://github.com/hack-ink/oauth2-broker/tags)
[![GitHub last commit](https://img.shields.io/github/last-commit/hack-ink/oauth2-broker?color=red&style=plastic)](https://github.com/hack-ink/oauth2-broker)
[![GitHub code lines](https://tokei.rs/b1/github/hack-ink/oauth2-broker)](https://github.com/hack-ink/oauth2-broker)

</div>

## Table of Contents

- [Why oauth2-broker?](#why-oauth2-broker)
- [Overview](#overview)
- [Quickstart](#quickstart)
- [Module Layout](#module-layout)
- [Broker Capabilities](#broker-capabilities)
- [Custom HTTP Transports](#custom-http-transports)
- [Feature Flags](#feature-flags)
- [Extension Traits](#extension-traits)
- [Observability](#observability)
- [Examples & Further Reading](#examples--further-reading)
- [Development Guardrails](#development-guardrails)
- [Support Me](#support-me)
- [Appreciation](#appreciation)
- [Additional Acknowledgements](#additional-acknowledgements)

## Why oauth2-broker?

- **Industry-grade OAuth 2.0 broker for Rust** — The ecosystem lacks a turnkey, multi-tenant token
  broker, forcing teams to rebuild authorization code, refresh, and service-to-service flows from
  scratch. This crate fills that gap with the explicit goal of delivering an industry-level control
  plane for OAuth clients.
- **Flow orchestration baked in** — `Broker::start_authorization`, `Broker::exchange_code`,
  `Broker::refresh_access_token`, and `Broker::client_credentials` already coordinate state, PKCE,
  caching, and persistence so product code can focus on user experience instead of grant semantics.
- **Deterministic storage + concurrency** — The `BrokerStore` trait, `MemoryStore`, `FileStore`,
  singleflight guard helpers, and `CachedTokenRequest` windows keep token records consistent while
  letting downstream crates plug in Redis, SQL, or bespoke backends without touching flow logic.
- **Pluggable HTTP + error mapping** — `TokenHttpClient`, `ReqwestHttpClient`,
  `Broker::with_http_client`, and `ResponseMetadataSlot` isolate transport wiring while
  `TransportErrorMapper` keeps error classification observable and stack-agnostic.
- **Operational visibility by default** — `FlowSpan`, `FlowOutcome`, `RefreshMetrics`, and
  provider-aware descriptors emit structured traces, counters, and tenant/provider labels so SREs
  can enforce budgets and SLAs without bolting on custom instrumentation.

## Overview

`oauth2-broker` exposes a `Broker<C, M>` facade that coordinates OAuth 2.0 flows for a single
`ProviderDescriptor`. Each broker instance owns the token store (`BrokerStore`), provider strategy,
HTTP client, and transport error mapper, so callers inject tenant/principal/scope context while the
crate reuses shared connection pools and descriptor metadata. Under the hood the crate drives the
upstream `oauth2` client through the `BasicFacade`, layering caching, concurrency control, and
observability on top.

The current codebase ships production-ready implementations for the flows already wired inside
`src/flows/`:

- `Broker::start_authorization` and `Broker::exchange_code` wrap Authorization Code + PKCE,
  generating state, PKCE pairs, and storing `TokenRecord` values after exchanging the returned
  `code`.
- `Broker::refresh_access_token` rotates refresh secrets via `BrokerStore::compare_and_swap_refresh`,
  records metrics through `RefreshMetrics`, and removes revoked tokens when providers return
  `invalid_grant`.
- `Broker::client_credentials` reuses cached service-to-service tokens, enforces jittered expiry
  windows via `CachedTokenRequest`, and uses per-`StoreKey` singleflight guards so concurrent
  callers ride the same refresh.

Caching and persistence are abstracted behind the `BrokerStore` trait, with in-tree backends for an
in-memory `MemoryStore` and a JSON-backed `FileStore`. Stores expose compare-and-swap refresh
semantics, revocation helpers, and a stable `StoreKey` fingerprint so downstream crates can add
Redis or SQL implementations without touching the flow code.

HTTP behavior is centralized in `TokenHttpClient` and `TransportErrorMapper`. The crate ships
`ReqwestHttpClient` plus `ReqwestTransportErrorMapper`, and any caller can replace them via
`Broker::with_http_client` to reuse custom TLS, retry, or proxy stacks. Each token request carries a
`ResponseMetadataSlot`, giving error mappers access to HTTP status codes and `Retry-After` hints
when translating transport failures.

Observability hooks live under `obs/`: every flow emits `FlowSpan` traces and success/attempt/failure
counters, while refresh operations also increment `RefreshMetrics`. Provider quirks and client-auth
rules are modeled by `ProviderDescriptor`, `GrantType`, and `ProviderStrategy`, so higher-level
systems configure descriptor data and then let the broker enforce those rules consistently across
every flow.

## Quickstart

```rust
use color_eyre::Result;
use oauth2_broker::{
	auth::{PrincipalId, ProviderId, ScopeSet, TenantId},
	flows::{Broker, CachedTokenRequest},
	provider::{DefaultProviderStrategy, GrantType, ProviderDescriptor, ProviderStrategy},
	store::{BrokerStore, MemoryStore},
};
use std::sync::Arc;
use url::Url;

#[tokio::main]
async fn main() -> Result<()> {
	color_eyre::install()?;

	let store: Arc<dyn BrokerStore> = Arc::new(MemoryStore::default());
	let strategy: Arc<dyn ProviderStrategy> = Arc::new(DefaultProviderStrategy);

	let descriptor = ProviderDescriptor::builder(ProviderId::new("demo-provider")?)
		.authorization_endpoint(Url::parse("https://provider.example.com/authorize")?)
		.token_endpoint(Url::parse("https://provider.example.com/token")?)
		.support_grants([
			GrantType::AuthorizationCode,
			GrantType::RefreshToken,
			GrantType::ClientCredentials,
		])
		.build()?;

	let broker = Broker::new(store, descriptor, strategy, "demo-client")
		.with_client_secret("demo-secret");

	let scope = ScopeSet::new(["email.read", "profile.read"])?;
	let request = CachedTokenRequest::new(
		TenantId::new("tenant-acme")?,
		PrincipalId::new("svc-router")?,
		scope,
	);

	let record = broker.client_credentials(request).await?;
	println!("access token: {}", record.access_token.expose());
	Ok(())
}
```

The snippet relies on the broker's default reqwest-backed transport, the in-memory store, and the
zero-cost `DefaultProviderStrategy` to reuse cached service-to-service tokens with the
`client_credentials` grant. For a mock-backed walkthrough that spins up an in-process
`httpmock` server, see [`examples/client_credentials.rs`](examples/client_credentials.rs);
an authorization-code state/PKCE walk-through lives in
[`examples/start_authorization.rs`](examples/start_authorization.rs).
A provider-specific Authorization Code + PKCE setup for X (Twitter) is available in
[`examples/x_authorization.rs`](examples/x_authorization.rs). It prints the X authorize URL,
prompts for the returned `state` and `code` via stdin, exchanges them, and can post a
tweet when you run `cargo make example-x-authorization` with real client credentials.

## Module Layout

- `src/flows/common.rs` centralizes scope formatting, token-response parsing, HTTP error mapping,
  and singleflight guard lookups. Flow-specific directories keep their heavy logic contained:
  `auth_code_pkce/session.rs` owns PKCE/session structs, `client_credentials/request.rs` holds the
  jittered cache request type, and `refresh/{request,metrics}.rs` split refresh inputs from the
  counter set shared with `Broker`.
- `src/provider/descriptor/` now mirrors the descriptor structure itself—`grant.rs` defines
  `GrantType`/`SupportedGrants`, `quirks.rs` captures `ProviderQuirks`, and `builder.rs` handles the
  builder plus validation. Customized HTTP behavior lives with `Broker::with_http_client`, so tests
  and downstream crates can inject any `TokenHttpClient` implementation without env-variable shims.
- `src/types/token/` separates concerns across `secret.rs`, `family.rs`, and `record.rs`, keeping the
  redacted secret wrapper isolated from the lifecycle-heavy record/builder logic.
- `src/obs/metrics.rs` and `src/obs/tracing.rs` keep feature-flagged observability hooks small so
  `obs/mod.rs` remains a thin façade.

## Broker Capabilities

### OAuth 2.0 flows (MVP)

- **Authorization Code + PKCE** — `Broker::start_authorization` generates state + PKCE material,
  with `Broker::exchange_code` handling HTTPS token exchanges, descriptor-driven PKCE
  enforcement, and store persistence.
- **Refresh Token** — `Broker::refresh_access_token` enforces singleflight guards per
  tenant/principal/scope tuple, rotates refresh tokens through the store’s CAS helpers, and
  surfaces telemetry via `RefreshMetrics`.
- **Client Credentials** — `Broker::client_credentials` reuses cached app-only tokens, joins
  scopes per provider delimiter, and re-enters the provider only when forced or nearing expiry.

### Storage & caching

- Public `BrokerStore` trait defines `fetch`, `save`, `revoke`, and refresh CAS semantics.
- `MemoryStore` (thread-safe) is the default backend for tests/examples; downstream integrators
  can implement `BrokerStore` for Redis, SQL, etc. without touching flows.

### HTTP handling

- Every broker owns a dedicated `TokenHttpClient` handle (`ReqwestHttpClient` by default), so
  downstream code never wires transports or toggles HTTP-specific feature flags unless they opt in.
- `Broker::with_http_client` accepts any type that implements `TokenHttpClient` plus a
  corresponding `TransportErrorMapper`, making it easy to reuse custom TLS, proxy, timeout, or
  entirely different HTTP stacks whenever the default transport is not sufficient. The same generic
  pair drives the internal `BasicFacade`, so every flow consistently works with custom transports.
- Token requests are constructed internally from descriptors, grant types, and strategies, keeping
  the public API focused on OAuth concepts instead of HTTP primitives.
- The crate always depends on `reqwest`, eliminating feature-flag drift between builds.

### Extension traits

- `RequestSignerExt` — describe how to attach broker-issued tokens to downstream HTTP clients.
- `TokenLeaseExt` — model short-lived access to cached records with readiness metadata.
- `RateLimitPolicy` — consult tenant/provider budgets and return `Allow`, `Delay`, or retry hints
  before flows hit upstream token endpoints.

### Observability & instrumentation

- Feature flag `tracing` emits `oauth2_broker.flow` spans for `authorization_code`, `refresh`,
  and `client_credentials` stages without leaking secrets.
- Feature flag `metrics` increments `oauth2_broker_flow_total` counters (labels: `flow`,
  `outcome`) so exporters such as Prometheus can track attempts/success/failure rates.
- Flows call into the observation helpers directly so downstream crates only need to opt into the
  features and provide their preferred subscriber/recorder configuration.

## Custom HTTP Transports

### Default transport

`Broker<C, M>` and the internal `BasicFacade<C, M>` are generic over both the transport and the
mapper. Calling `Broker::new` instantiates those generics as
`Broker<ReqwestHttpClient, ReqwestTransportErrorMapper>`, which keeps the Quickstart and HTTP-backed
examples zero-config. `TokenHttpClient`, `ResponseMetadata`, `ResponseMetadataSlot`, and
`TransportErrorMapper` are re-exported from the crate root so downstream crates can wire their own
stack without depending on private modules.

### Registering a custom transport

When you need to wrap an alternate pool, TLS stack, or test double, call
`Broker::with_http_client(store, descriptor, strategy, client_id, my_client, my_mapper)` and follow
these steps:

1. Implement `TokenHttpClient` for your transport. The `Handle` type you expose must implement
   `oauth2::AsyncHttpClient` and stay `Send + 'static`. The associated `TransportError` can be any
   `Send + Sync + 'static` value, so your stack never has to reference `reqwest::Error`.
2. Emit `ResponseMetadata` by cloning the provided `ResponseMetadataSlot`, calling `slot.take()`
   before dispatching the request, and persisting status plus `Retry-After` via `slot.store(...)` as
   soon as headers arrive.
3. Implement `TransportErrorMapper<TransportError>` so the broker can translate
   `HttpClientError<TransportError>` plus metadata into its `Error` classification.
4. Wrap both handles in `Arc` (the broker clones them internally) and pass them to
   `Broker::with_http_client` alongside your descriptor, provider strategy, and OAuth client ID.

`examples/custom_transport.rs` contains a complete walkthrough that registers a mock transport with
a bespoke error type while keeping metadata and mapper wiring intact.

### TokenHttpClient contract

`TokenHttpClient` hands `oauth2` an `AsyncHttpClient` handle that owns a clone of a
`ResponseMetadataSlot`, ensuring every transport stores the final HTTP status and `Retry-After`
hints in a [`ResponseMetadata`] value. Implementations must:

1. Call `slot.take()` before dispatching the request so stale metadata never leaks between retries.
2. Populate `ResponseMetadata` via `slot.store(...)` as soon as the status/headers are available.
3. Return an `AsyncHttpClient` handle whose future is `Send + 'static` so broker flows can box it.
4. Propagate the associated `TransportError` type through `AsyncHttpClient::Error`.

The `ResponseMetadataSlot` and `ResponseMetadata` types are re-exported from the crate root, which
makes it easy to satisfy the contract without digging through internal modules.

### Mapper requirements

Whenever a transport emits `HttpClientError<E>`, the mapper receives the provider strategy, active
grant, and the freshest metadata. The trait signature is intentionally public so you can depend on
it directly:

```rust
pub trait TransportErrorMapper<E>: Send + Sync + 'static {
	fn map_transport_error(
		&self,
		strategy: &dyn ProviderStrategy,
		grant: GrantType,
		metadata: Option<&ResponseMetadata>,
		error: HttpClientError<E>,
	) -> oauth2_broker::error::Error;
}
```

Use this callback to translate transport-specific errors into `TransientError`, `TransportError`,
or any other variant that callers rely on for retry/backoff logic. In practice, mappers should:

- Inspect `ResponseMetadata` for HTTP status and `Retry-After` hints before picking a retry class.
- Treat `HttpClientError::Reqwest(inner)` as "transport error" even if `inner` is your custom
  `TransportError`. The upstream `oauth2` crate kept the variant name for compatibility while the
  payload type is now generic.
- Fall back to `HttpClientError::Other`, `HttpClientError::Http`, and `HttpClientError::Io` to
  retain error context that does not come from the transport.

`ReqwestTransportErrorMapper` demonstrates how reqwest errors become broker `Error` values, and the
custom transport example mirrors the exact pattern for a mock error type.

### Registering the client and mapper

Both the client and mapper typically live behind `Arc` handles so every broker instance can share
them:

```rust
let http_client = Arc::new(MockHttpClient::default());
let mapper = Arc::new(MockTransportErrorMapper::default());
let broker = Broker::with_http_client(store, descriptor, strategy, "demo-client", http_client, mapper)
    .with_client_secret("demo-secret");
```

The [`examples/custom_transport.rs`](examples/custom_transport.rs) walkthrough demonstrates a mock
transport with a non-reqwest error type, ensures metadata recording still works, and wires a mapper
that forwards those errors to the broker. Use it as a template whenever you need to plug in a
custom HTTP stack, simulator, or integration-test fake.

## Feature Flags

| Feature   | Default | Description                                                                                             |
| --------- | ------- | ------------------------------------------------------------------------------------------------------- |
| `tracing` | ❌      | Emits `tracing` spans named `oauth2_broker.flow` so downstream apps can correlate grant attempts.       |
| `metrics` | ❌      | Increments the `oauth2_broker_flow_total` counter via the `metrics` crate with `flow`/`outcome` labels. |

## Extension Traits

The MVP ships **contracts only** for higher-level integrations so downstream crates can
experiment without waiting on broker-owned implementations:

- `ext::RequestSignerExt<Request, Error>` — describes how to attach broker-issued tokens to any
  request builder (the docs show a `reqwest::RequestBuilder` example).
- `ext::TokenLeaseExt<Lease, Error>` — models short-lived access to a `TokenRecord` via
  lease/guard types along with supporting metadata (`TokenLeaseContext`, `TokenLeaseState`).
- `ext::RateLimitPolicy<Error>` — lets flows consult tenant/provider rate budgets before hitting
  providers using `RateLimitContext`, `RateLimitDecision`, and `RetryDirective` helpers.

All three traits live under `src/ext/`, include doc-tested examples, and intentionally ship **no
default implementations** in this MVP so consumers can plug their own HTTP stack, token cache, and
rate-limit store without extra dependencies.

## Observability

Tracing + metrics ship **disabled by default** so downstream crates only pay for what they enable.
Turn them on explicitly in `Cargo.toml`:

```toml
[dependencies]
oauth2-broker = { version = "0.0.1", features = ["tracing", "metrics"] }
```

- `tracing` creates spans named `oauth2_broker.flow` with `flow` (`authorization_code`,
  `refresh`, or `client_credentials`) and `stage` (`start_authorization`, `exchange_code`, etc.).
  Only enum labels are recorded so client IDs, secrets, and tokens never leave the crate. You can
  also open spans in your own adapters using the helpers:

    ```rust
    #[cfg(feature = "tracing")]
    {
    	use oauth2_broker::obs::{FlowKind, FlowSpan};
    	let _guard = FlowSpan::new(FlowKind::AuthorizationCode, "my_adapter").entered();
    }
    ```

- `metrics` increments a counter named `oauth2_broker_flow_total` via the `metrics` crate every
  time a flow attempts, succeeds, or fails. Labels mirror the tracing fields so exporters like
  Prometheus or OpenTelemetry can break down rates per grant/outcome:

    ```rust
    #[cfg(feature = "metrics")]
    {
    	use oauth2_broker::obs::{record_flow_outcome, FlowKind, FlowOutcome};
    	record_flow_outcome(FlowKind::ClientCredentials, FlowOutcome::Attempt);
    }
    ```

Set up your preferred `tracing` subscriber and `metrics` recorder (for example,
`metrics-exporter-prometheus`) to collect the emitted data.

## Examples & Further Reading

- [`examples/client_credentials.rs`](examples/client_credentials.rs) — spins up an `httpmock`
  server, builds a broker with the default reqwest client, and mirrors the Quickstart flow without
  touching external networks.
- [`examples/custom_transport.rs`](examples/custom_transport.rs) — shows how to register a custom
  `TokenHttpClient` plus mapper so transports that do not use reqwest can participate in flows.
- [`examples/start_authorization.rs`](examples/start_authorization.rs) — shows how to generate an
  `AuthorizationSession`, persist/lookup `state`, and surface PKCE material around a redirect.
- [`docs/DESIGN.md`](docs/DESIGN.md) — design outline plus the Release Overview section for the
  MVP crate map, extension traits, observability model, and explicit out-of-scope decisions.
- [`CHANGELOG.md`](CHANGELOG.md) — dated release notes (0.0.1 captures the MVP surface).
- [`CONTRIBUTING.md`](CONTRIBUTING.md) — guardrails, quality gates, and reporting instructions.

## Development Guardrails

The tests cover the reqwest-backed flows against an `httpmock` server plus the
authorization, refresh, and client-credentials flows end to end.

## Support Me

If you find this project helpful and would like to support its development, you can buy me a coffee!

Your support is greatly appreciated and motivates me to keep improving this project.

- **Fiat**
    - [Ko-fi](https://ko-fi.com/hack_ink)
    - [爱发电](https://afdian.com/a/hack_ink)
- **Crypto**
    - **Bitcoin**
        - `bc1pedlrf67ss52md29qqkzr2avma6ghyrt4jx9ecp9457qsl75x247sqcp43c`
    - **Ethereum**
        - `0x3e25247CfF03F99a7D83b28F207112234feE73a6`
    - **Polkadot**
        - `156HGo9setPcU2qhFMVWLkcmtCEGySLwNqa3DaEiYSWtte4Y`

Thank you for your support!

## Appreciation

We would like to extend our heartfelt gratitude to the following projects and contributors:

Grateful for the Rust community and the maintainers of `reqwest`, `oauth2`, `metrics`, and `tracing`, whose work makes this cache possible.

## Additional Acknowledgements

- TODO

<div align="right">

### License

<sup>Licensed under [GPL-3.0](LICENSE).</sup>

</div>
