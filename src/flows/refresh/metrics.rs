// std
use std::sync::atomic::{AtomicU64, Ordering};

/// Thread-safe counters for refresh attempts.
#[derive(Debug, Default)]
pub struct RefreshMetrics {
	attempts: AtomicU64,
	success: AtomicU64,
	failure: AtomicU64,
}
impl RefreshMetrics {
	/// Returns the total number of refresh attempts.
	pub fn attempts(&self) -> u64 {
		self.attempts.load(Ordering::Relaxed)
	}

	/// Returns the number of successful refresh calls (including cache reuses).
	pub fn successes(&self) -> u64 {
		self.success.load(Ordering::Relaxed)
	}

	/// Returns the number of failed refresh calls.
	pub fn failures(&self) -> u64 {
		self.failure.load(Ordering::Relaxed)
	}

	pub(crate) fn record_attempt(&self) {
		self.attempts.fetch_add(1, Ordering::Relaxed);
	}

	pub(crate) fn record_success(&self) {
		self.success.fetch_add(1, Ordering::Relaxed);
	}

	pub(crate) fn record_failure(&self) {
		self.failure.fetch_add(1, Ordering::Relaxed);
	}
}
