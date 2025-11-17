// self
use crate::obs::{FlowKind, FlowOutcome};

/// Records a flow outcome via the global metrics recorder (when enabled).
pub fn record_flow_outcome(kind: FlowKind, outcome: FlowOutcome) {
	#[cfg(feature = "metrics")]
	{
		metrics::counter!(
			"oauth2_broker_flow_total",
			"flow" => kind.as_str(),
			"outcome" => outcome.as_str()
		)
		.increment(1);
	}

	#[cfg(not(feature = "metrics"))]
	{
		let _ = (kind, outcome);
	}
}

#[cfg(test)]
mod tests {
	// self
	use super::*;

	#[test]
	fn record_flow_outcome_noop_without_metrics() {
		record_flow_outcome(FlowKind::AuthorizationCode, FlowOutcome::Failure);
	}
}
