//! Scope modeling helpers used across the broker.

// std
use std::{
	cmp::Ordering,
	collections::BTreeSet,
	hash::{Hash, Hasher},
	slice::Iter,
	sync::OnceLock,
};
// crates.io
use base64::{Engine as _, engine::general_purpose::STANDARD_NO_PAD};
use serde::{Deserializer, Serializer, de::Error as DeError, ser::SerializeSeq};
use sha2::{Digest, Sha256};
// self
use crate::_prelude::*;

/// Errors emitted when validating scopes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ThisError)]

pub enum ScopeValidationError {
	/// Empty scope entries are not allowed.
	#[error("Scope entries cannot be empty.")]
	Empty,
	/// Scopes cannot contain embedded whitespace characters.
	#[error("Scope contains whitespace: {scope}.")]
	ContainsWhitespace {
		/// The offending scope string.
		scope: String,
	},
}

/// Normalized set of OAuth scopes with a stable fingerprint cache.
///
/// Scopes are deduplicated and sorted so equality, ordering, and hashing
/// remain consistent across platforms. The [`fingerprint`](Self::fingerprint) helper
/// lazily caches a base64 (no padding) SHA-256 digest of the normalized string and
/// the [`Hash`] implementation reuses that cache so hashing stays stable without
/// re-normalizing the strings.
#[derive(Default)]
pub struct ScopeSet {
	/// The normalized scopes.
	pub scopes: Arc<[String]>,
	/// The fingerprint of the normalized scopes.
	pub fingerprint_cache: OnceLock<String>,
}
impl ScopeSet {
	/// Creates a normalized scope set from any iterator.
	pub fn new<I, S>(scopes: I) -> Result<Self, ScopeValidationError>
	where
		I: IntoIterator<Item = S>,
		S: Into<String>,
	{
		Ok(Self { scopes: normalize(scopes)?, fingerprint_cache: OnceLock::new() })
	}

	/// Number of distinct scopes.
	pub fn len(&self) -> usize {
		self.scopes.len()
	}

	/// Returns true if no scopes are defined.
	pub fn is_empty(&self) -> bool {
		self.scopes.is_empty()
	}

	/// Returns true if the normalized set contains the provided scope.
	pub fn contains(&self, scope: &str) -> bool {
		self.scopes.binary_search_by(|candidate| candidate.as_str().cmp(scope)).is_ok()
	}

	/// Iterator over normalized scopes.
	pub fn iter(&self) -> impl Iterator<Item = &str> {
		self.scopes.iter().map(|s| s.as_str())
	}

	/// Returns the normalized string representation (space-delimited).
	pub fn normalized(&self) -> String {
		self.scopes.join(" ")
	}

	/// Stable fingerprint derived from the normalized scope list.
	///
	/// The fingerprint is a base64 (no padding) encoding of the SHA-256 digest for the
	/// normalized, space-delimited scope string and is cached after the first
	/// calculation.
	pub fn fingerprint(&self) -> String {
		self.fingerprint_cache.get_or_init(|| compute_fingerprint(&self.scopes)).clone()
	}

	/// Returns the underlying slice of scope strings.
	pub fn as_slice(&self) -> &[String] {
		&self.scopes
	}
}
impl Clone for ScopeSet {
	fn clone(&self) -> Self {
		Self { scopes: self.scopes.clone(), fingerprint_cache: OnceLock::new() }
	}
}
impl PartialEq for ScopeSet {
	fn eq(&self, other: &Self) -> bool {
		self.scopes == other.scopes
	}
}
impl Eq for ScopeSet {}
impl PartialOrd for ScopeSet {
	fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
		Some(self.cmp(other))
	}
}
impl Ord for ScopeSet {
	fn cmp(&self, other: &Self) -> Ordering {
		self.scopes.cmp(&other.scopes)
	}
}
impl Hash for ScopeSet {
	fn hash<H: Hasher>(&self, state: &mut H) {
		self.fingerprint_cache.get_or_init(|| compute_fingerprint(&self.scopes)).hash(state);
	}
}
impl Debug for ScopeSet {
	fn fmt(&self, f: &mut Formatter) -> FmtResult {
		f.debug_tuple("ScopeSet").field(&self.scopes).finish()
	}
}
impl Display for ScopeSet {
	fn fmt(&self, f: &mut Formatter) -> FmtResult {
		f.write_str(&self.normalized())
	}
}

/// Iterator over scope strings.
pub struct ScopeIter<'a> {
	inner: Iter<'a, String>,
}
impl<'a> Iterator for ScopeIter<'a> {
	type Item = &'a str;

	fn next(&mut self) -> Option<Self::Item> {
		self.inner.next().map(|s| s.as_str())
	}
}
impl TryFrom<Vec<String>> for ScopeSet {
	type Error = ScopeValidationError;

	fn try_from(value: Vec<String>) -> Result<Self, Self::Error> {
		Self::new(value)
	}
}
impl TryFrom<&[String]> for ScopeSet {
	type Error = ScopeValidationError;

	fn try_from(value: &[String]) -> Result<Self, Self::Error> {
		Self::new(value.to_vec())
	}
}
impl<'a> IntoIterator for &'a ScopeSet {
	type IntoIter = ScopeIter<'a>;
	type Item = &'a str;

	fn into_iter(self) -> Self::IntoIter {
		ScopeIter { inner: self.scopes.iter() }
	}
}
impl FromStr for ScopeSet {
	type Err = ScopeValidationError;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		if s.is_empty() {
			return Ok(Self::default());
		}
		if s.chars().all(char::is_whitespace) {
			return Err(ScopeValidationError::Empty);
		}

		Self::new(s.split_whitespace())
	}
}
impl Serialize for ScopeSet {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		let mut seq = serializer.serialize_seq(Some(self.scopes.len()))?;

		for scope in self.scopes.iter() {
			seq.serialize_element(scope)?;
		}

		seq.end()
	}
}
impl<'de> Deserialize<'de> for ScopeSet {
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
	where
		D: Deserializer<'de>,
	{
		let values = <Vec<String>>::deserialize(deserializer)?;

		ScopeSet::new(values).map_err(DeError::custom)
	}
}

fn normalize<I, S>(scopes: I) -> Result<Arc<[String]>, ScopeValidationError>
where
	I: IntoIterator<Item = S>,
	S: Into<String>,
{
	let mut set = BTreeSet::new();

	for scope in scopes {
		let owned: String = scope.into();

		if owned.is_empty() {
			return Err(ScopeValidationError::Empty);
		}
		if owned.chars().any(char::is_whitespace) {
			return Err(ScopeValidationError::ContainsWhitespace { scope: owned });
		}

		set.insert(owned);
	}

	Ok(Arc::from(set.into_iter().collect::<Vec<_>>()))
}

fn compute_fingerprint(scopes: &[String]) -> String {
	let normalized = scopes.join(" ");
	let mut hasher = Sha256::new();

	hasher.update(normalized.as_bytes());

	let digest = hasher.finalize();

	STANDARD_NO_PAD.encode(digest)
}

#[cfg(test)]
mod tests {
	// self
	use super::*;

	#[test]
	fn scopes_normalize_and_hash_stably() {
		let lhs = ScopeSet::new(["profile", "email", "email"])
			.expect("Left-hand scope set should be valid.");
		let rhs =
			ScopeSet::new(["email", "profile"]).expect("Right-hand scope set should be valid.");

		assert_eq!(lhs, rhs);
		assert_eq!(lhs.normalized(), "email profile");
		assert_eq!(lhs.fingerprint(), rhs.fingerprint());
	}

	#[test]
	fn scopes_reject_whitespace_padding() {
		let err = ScopeSet::new([" profile "]).expect_err("Padded scopes must be rejected.");

		assert!(matches!(err, ScopeValidationError::ContainsWhitespace { .. }));
		assert!(ScopeSet::from_str("").is_ok(), "Empty string represents an empty scope set.");
		assert!(ScopeSet::from_str("   ").is_err(), "Whitespace-only input must be rejected.");
	}

	#[test]
	fn invalid_scopes_error() {
		assert!(ScopeSet::new([""]).is_err());
		assert!(ScopeSet::new(["contains space"]).is_err());
	}

	#[test]
	fn iter_and_contains_work() {
		let scopes =
			ScopeSet::from_str("email profile").expect("Scope string should parse successfully.");

		assert!(scopes.contains("email"));
		assert_eq!(scopes.iter().collect::<Vec<_>>(), vec!["email", "profile"]);

		let fp1 = scopes.fingerprint();
		let fp2 = scopes.fingerprint();

		assert_eq!(fp1, fp2, "Fingerprint should be cached and stable.");
	}

	#[test]
	fn try_from_slice_round_trips() {
		let raw = vec!["read".to_string(), "write".to_string()];
		let set = ScopeSet::try_from(raw.as_slice())
			.expect("Slice-based scope set should build successfully.");

		assert_eq!(set.len(), 2);

		let expected = vec!["read".to_string(), "write".to_string()];

		assert_eq!(set.as_slice(), expected.as_slice());
	}
}
