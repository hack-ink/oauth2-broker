// self
use crate::{_prelude::*, obs::FlowKind};

/// Type alias that resolves to an instrumented future when tracing is enabled.
#[cfg(feature = "tracing")]
pub type InstrumentedFlow<F> = tracing::instrument::Instrumented<F>;
/// Passthrough future type when tracing is disabled.
#[cfg(not(feature = "tracing"))]
pub type InstrumentedFlow<F> = F;

/// A span builder used by broker flows.
#[derive(Clone, Debug)]
pub struct FlowSpan {
	#[cfg(feature = "tracing")]
	span: tracing::Span,
}
impl FlowSpan {
	/// Creates a new span tagged with the provided flow kind + stage.
	pub fn new(kind: FlowKind, stage: &'static str) -> Self {
		#[cfg(feature = "tracing")]
		{
			let span = tracing::info_span!("oauth2_broker.flow", flow = kind.as_str(), stage);

			Self { span }
		}
		#[cfg(not(feature = "tracing"))]
		{
			let _ = (kind, stage);

			Self {}
		}
	}

	/// Enters the span for synchronous sections.
	pub fn entered(self) -> FlowSpanGuard {
		#[cfg(feature = "tracing")]
		{
			FlowSpanGuard { guard: self.span.entered() }
		}
		#[cfg(not(feature = "tracing"))]
		{
			let _ = self;

			FlowSpanGuard {}
		}
	}

	/// Instruments an async block without holding a guard across `.await` points.
	pub fn instrument<Fut>(&self, fut: Fut) -> InstrumentedFlow<Fut>
	where
		Fut: Future,
	{
		#[cfg(feature = "tracing")]
		{
			use tracing::Instrument;

			fut.instrument(self.span.clone())
		}
		#[cfg(not(feature = "tracing"))]
		{
			fut
		}
	}
}

/// RAII guard returned by [`FlowSpan::entered`].
pub struct FlowSpanGuard {
	#[cfg(feature = "tracing")]
	#[allow(dead_code)]
	guard: tracing::span::EnteredSpan,
}
impl Debug for FlowSpanGuard {
	fn fmt(&self, f: &mut Formatter) -> FmtResult {
		f.write_str("FlowSpanGuard(..)")
	}
}

#[cfg(test)]
mod tests {
	// self
	use super::*;

	#[test]
	fn flow_span_noop_without_tracing() {
		let _guard = FlowSpan::new(FlowKind::ClientCredentials, "test").entered();
		// Compile-time smoke test ensures the guard exists even when tracing is disabled.
	}

	#[cfg(feature = "tracing")]
	#[tokio::test]
	async fn instrument_wraps_future() {
		let span = FlowSpan::new(FlowKind::Refresh, "instrument_wraps_future");
		let value = span.instrument(async { 42 }).await;

		assert_eq!(value, 42);
	}
}
