// crates.io
use time::macros;
// self
use oauth2_broker::{
	_preludet::*,
	auth::{PrincipalId, ScopeSet, TenantId, TokenFamily, TokenRecord, TokenStatus},
	store::{BrokerStore, CompareAndSwapOutcome, MemoryStore},
};

fn make_family() -> TokenFamily {
	let tenant = TenantId::new("tenant-123")
		.expect("Failed to build tenant identifier for memory store tests.");
	let principal = PrincipalId::new("principal-456")
		.expect("Failed to build principal identifier for memory store tests.");

	TokenFamily::new(tenant, principal)
}

fn make_scope() -> ScopeSet {
	ScopeSet::new(["email", "profile"]).expect("Failed to build default scope set for tests.")
}

fn build_record(
	family: &TokenFamily,
	scope: &ScopeSet,
	access: &str,
	refresh: Option<&str>,
) -> TokenRecord {
	let issued = macros::datetime!(2025-11-10 12:00 UTC);
	let expires = issued + Duration::hours(1);
	let mut builder = TokenRecord::builder(family.clone(), scope.clone())
		.access_token(access.to_string())
		.issued_at(issued)
		.expires_at(expires);

	if let Some(value) = refresh {
		builder = builder.refresh_token(value.to_string());
	}

	builder.build().expect("Token record fixture should build successfully.")
}

#[tokio::test]
async fn save_and_fetch_round_trip() {
	let store = MemoryStore::default();
	let family = make_family();
	let scope = make_scope();
	let record = build_record(&family, &scope, "access-1", Some("refresh-1"));

	store
		.save(record.clone())
		.await
		.expect("Saving record fixture into memory store should succeed.");

	let fetched = store
		.fetch(&family, &scope)
		.await
		.expect("Fetching token record from memory store should succeed.")
		.expect("Stored record should remain present.");

	assert_eq!(fetched.access_token.expose(), record.access_token.expose());
	assert_eq!(
		fetched.refresh_token.as_ref().map(|secret| secret.expose()),
		record.refresh_token.as_ref().map(|secret| secret.expose())
	);
}

#[tokio::test]
async fn cas_success_and_mismatch() {
	let store = MemoryStore::default();
	let family = make_family();
	let scope = make_scope();
	let initial = build_record(&family, &scope, "access-initial", Some("refresh-old"));

	store
		.save(initial.clone())
		.await
		.expect("Saving initial record into memory store should succeed.");

	let replacement = build_record(&family, &scope, "access-new", Some("refresh-new"));
	let outcome = store
		.compare_and_swap_refresh(
			&family,
			&scope,
			initial.refresh_token.as_ref().map(|secret| secret.expose()),
			replacement.clone(),
		)
		.await
		.expect("CAS operation should succeed when refresh tokens match.");

	assert_eq!(outcome, CompareAndSwapOutcome::Updated);

	let fetched = store
		.fetch(&family, &scope)
		.await
		.expect("Fetching updated record should succeed.")
		.expect("Updated record should remain present.");

	assert_eq!(fetched.refresh_token.as_ref().map(|secret| secret.expose()), Some("refresh-new"));

	let mismatch = store
		.compare_and_swap_refresh(&family, &scope, Some("refresh-old"), replacement)
		.await
		.expect("CAS should report a refresh mismatch when tokens differ.");

	assert_eq!(mismatch, CompareAndSwapOutcome::RefreshMismatch);

	let missing_scope =
		ScopeSet::new(["offline_access"]).expect("Missing scope set should build successfully.");
	let missing = store
		.compare_and_swap_refresh(&family, &missing_scope, Some("whatever"), initial)
		.await
		.expect("CAS should report a missing record for unknown scopes.");

	assert_eq!(missing, CompareAndSwapOutcome::Missing);
}

#[tokio::test]
async fn concurrent_cas_allows_single_winner() {
	let store = MemoryStore::default();
	let family = make_family();
	let scope = make_scope();
	let base = build_record(&family, &scope, "access-base", Some("refresh-base"));

	store.save(base.clone()).await.expect("Saving base record into memory store should succeed.");

	let expected = base
		.refresh_token
		.as_ref()
		.map(|secret| secret.expose().to_string())
		.expect("Base record should contain a refresh token.");
	let store_a = store.clone();
	let store_b = store.clone();
	let family_a = family.clone();
	let family_b = family.clone();
	let scope_a = scope.clone();
	let scope_b = scope.clone();
	let expected_a = expected.clone();
	let expected_b = expected;
	let task_a = tokio::spawn(async move {
		let replacement = build_record(&family_a, &scope_a, "access-a", Some("refresh-a"));
		store_a
			.compare_and_swap_refresh(&family_a, &scope_a, Some(expected_a.as_str()), replacement)
			.await
			.expect("CAS task A should complete successfully.")
	});
	let task_b = tokio::spawn(async move {
		let replacement = build_record(&family_b, &scope_b, "access-b", Some("refresh-b"));
		store_b
			.compare_and_swap_refresh(&family_b, &scope_b, Some(expected_b.as_str()), replacement)
			.await
			.expect("CAS task B should complete successfully.")
	});
	let (outcome_a, outcome_b): (
		Result<CompareAndSwapOutcome, tokio::task::JoinError>,
		Result<CompareAndSwapOutcome, tokio::task::JoinError>,
	) = tokio::join!(task_a, task_b);
	let outcome_a = outcome_a.expect("CAS task A should not panic.");
	let outcome_b = outcome_b.expect("CAS task B should not panic.");
	let successes = [outcome_a, outcome_b]
		.iter()
		.filter(|outcome| matches!(outcome, CompareAndSwapOutcome::Updated))
		.count();

	assert_eq!(successes, 1, "only one CAS should succeed");

	let final_record = store
		.fetch(&family, &scope)
		.await
		.expect("Fetching final record should succeed.")
		.expect("Final record should remain present.");

	assert!(matches!(
		final_record.refresh_token.as_ref().map(|secret| secret.expose()),
		Some("refresh-a") | Some("refresh-b")
	));
}

#[tokio::test]
async fn cas_supports_records_without_refresh_tokens() {
	let store = MemoryStore::default();
	let family = make_family();
	let scope = make_scope();
	let record_without_refresh = build_record(&family, &scope, "access", None);

	store
		.save(record_without_refresh.clone())
		.await
		.expect("Saving record without a refresh token should succeed.");

	let replacement = build_record(&family, &scope, "access-updated", None);
	let outcome = store
		.compare_and_swap_refresh(&family, &scope, None, replacement)
		.await
		.expect("CAS should succeed when both sides have no refresh token.");

	assert_eq!(outcome, CompareAndSwapOutcome::Updated);
}

#[tokio::test]
async fn revoke_marks_records() {
	let store = MemoryStore::default();
	let family = make_family();
	let scope = make_scope();
	let record = build_record(&family, &scope, "access", Some("refresh"));

	store.save(record.clone()).await.expect("Saving revocable record should succeed.");

	let instant = OffsetDateTime::now_utc();
	let revoked = store
		.revoke(&family, &scope, instant)
		.await
		.expect("Revocation operation should succeed.")
		.expect("Revocation should return the affected record.");

	assert_eq!(revoked.revoked_at, Some(instant));
	assert_eq!(revoked.status_at(instant), TokenStatus::Revoked);

	let fetched = store
		.fetch(&family, &scope)
		.await
		.expect("Fetching revoked record should succeed.")
		.expect("Revoked record should remain present for inspection.");

	assert_eq!(fetched.revoked_at, Some(instant));
}

#[tokio::test]
async fn revoke_returns_none_for_missing_record() {
	let store = MemoryStore::default();
	let family = make_family();
	let scope = make_scope();
	let instant = OffsetDateTime::now_utc();
	let outcome = store
		.revoke(&family, &scope, instant)
		.await
		.expect("Revocation should not error when the record is missing.");

	assert!(outcome.is_none());
}
